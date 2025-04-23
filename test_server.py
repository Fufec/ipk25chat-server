#!/usr/bin/env python3

import asyncio
import socket
import struct
import argparse
import logging
import time
import random
import signal
from collections import defaultdict, deque
from asyncio import Lock # Import Lock

# --- Configuration ---
DEFAULT_PORT = 4567
DEFAULT_TIMEOUT_MS = 250  # Corresponds to client's -d
DEFAULT_RETRIES = 3       # Corresponds to client's -r
PING_INTERVAL_S = 45      # How often server sends PING to UDP clients
REPLY_TIMEOUT_S = 5       # How long server waits for internal tasks (not protocol defined)
MAX_UDP_PAYLOAD = 65507     # Theoretical max UDP payload size
MAX_TCP_LINE = 61000      # Generous buffer for TCP lines (content + headers)
LOG_LEVEL = logging.DEBUG # Change to logging.DEBUG for more verbose output

# --- Protocol Constants ---
# Message Types (UDP)
TYPE_CONFIRM = 0x00
TYPE_REPLY = 0x01
TYPE_AUTH = 0x02
TYPE_JOIN = 0x03
TYPE_MSG = 0x04
TYPE_PING = 0xFD
TYPE_ERR = 0xFE
TYPE_BYE = 0xFF

TYPE_NAMES = {
    0x00: "CONFIRM", 0x01: "REPLY", 0x02: "AUTH", 0x03: "JOIN",
    0x04: "MSG", 0xFD: "PING", 0xFE: "ERR", 0xFF: "BYE"
}

# Hardcoded credentials for testing
# In a real scenario, use a database or proper auth system
USER_CREDENTIALS = {
    "test": "test",
    "user": "user",
    "alice": "secret",
    "bob": "bob",
    "frank": "frank"
    # Add your VUT login and the secret GUID you received
    # "vutlogin": "your-guid-secret"
}

# --- Logging Setup ---
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s',
    datefmt='%H:%M:%S'
)

# --- Server State ---
# Use asyncio Locks to protect shared state accessed by concurrent handlers/tasks
clients = {}  # {(transport_type, remote_addr): client_info}
channels = defaultdict(set)  # {channel_id: {client_key, ...}}
udp_listeners = {} # {socket: UdpProtocolInstance}
udp_pending_confirms = {} # { (client_key, msg_id): { 'message': bytes, 'retries_left': int, 'task': asyncio.Task, 'send_time': float } }

clients_lock = Lock()
channels_lock = Lock()
udp_listeners_lock = Lock()
udp_confirms_lock = Lock()

server_shutdown_event = asyncio.Event()

# --- Helper Functions ---

def get_client_key(transport_type, remote_addr):
    """Generates a unique key for a client."""
    return (transport_type.lower(), remote_addr) # e.g., ('tcp', ('127.0.0.1', 12345)) or ('udp', ('127.0.0.1', 54321))

def parse_udp_message(data):
    """Parses a UDP message, returns (type, msg_id, fields) or raises ValueError."""
    # Check minimum size (CONFIRM is the smallest valid message)
    if len(data) < 3: #<-- CONFIRM is exactly 3 bytes
        raise ValueError("UDP message too short (minimum 3 bytes required)")

    # --- Corrected CONFIRM Handling ---
    msg_type = data[0] # Type is the first byte

    if msg_type == TYPE_CONFIRM:
        # For CONFIRM, the "msg_id" field in the header IS the Ref_MessageID
        # according to the spec diagrams (1 byte type + 2 bytes RefID).
        if len(data) != 3: # CONFIRM must be exactly 3 bytes
             raise ValueError(f"Invalid CONFIRM message size: expected 3, got {len(data)}")
        # Unpack the RefID from bytes 1 and 2
        ref_msg_id = struct.unpack('>H', data[1:3])[0]
        fields = {'ref_msg_id': ref_msg_id}
        # CONFIRM messages don't have their *own* sequential MsgID in the spec examples
        # We'll return 0 as the placeholder MsgID for CONFIRM itself.
        msg_id = 0
        logging.debug(f"Parsed UDP msg: Type=CONFIRM({msg_type:#04x}), RefID={ref_msg_id}, (Own MsgID=N/A)")
        return msg_type, msg_id, fields
    # --- End Corrected CONFIRM Handling ---

    # --- Handling for other message types (which have their own MsgID) ---
    # These messages MUST have at least the standard 3-byte header
    if len(data) < 3:
         # This check is now technically redundant due to the check at the start,
         # but harmless to leave for clarity if msg_type wasn't CONFIRM.
         raise ValueError("UDP message too short for standard header")

    msg_type, msg_id = struct.unpack('>BH', data[:3]) # Unpack standard header
    fields = {}
    payload = data[3:] # Payload starts after standard header for these types

    try:
        # Original parsing logic for types other than CONFIRM:
        if msg_type == TYPE_REPLY:
            if len(payload) < 3: raise ValueError("Invalid REPLY payload size")
            fields['result'] = payload[0]
            fields['ref_msg_id'] = struct.unpack('>H', payload[1:3])[0]
            fields['message_content'] = payload[3:].split(b'\0', 1)[0].decode('ascii')
        elif msg_type == TYPE_AUTH:
            # ... (rest of original parsing logic for AUTH, JOIN, MSG, ERR, BYE, PING) ...
            parts = payload.split(b'\0', 3)
            if len(parts) != 4 or parts[3] != b'': raise ValueError("Invalid AUTH format")
            fields['username'] = parts[0].decode('ascii')
            fields['display_name'] = parts[1].decode('ascii')
            fields['secret'] = parts[2].decode('ascii')
        elif msg_type == TYPE_JOIN:
            parts = payload.split(b'\0', 2)
            if len(parts) != 3 or parts[2] != b'': raise ValueError("Invalid JOIN format")
            fields['channel_id'] = parts[0].decode('ascii')
            fields['display_name'] = parts[1].decode('ascii')
        elif msg_type == TYPE_MSG or msg_type == TYPE_ERR:
            parts = payload.split(b'\0', 2)
            if len(parts) != 3 or parts[2] != b'': raise ValueError(f"Invalid {TYPE_NAMES[msg_type]} format")
            fields['display_name'] = parts[0].decode('ascii')
            fields['message_content'] = parts[1].decode('ascii')
        elif msg_type == TYPE_BYE:
            parts = payload.split(b'\0', 1)
            if len(parts) != 2 or parts[1] != b'': raise ValueError("Invalid BYE format")
            fields['display_name'] = parts[0].decode('ascii')
        elif msg_type == TYPE_PING:
            if len(payload) != 0: raise ValueError("Invalid PING payload size")
        else:
            # Already handled CONFIRM, so this should be an unknown type
            raise ValueError(f"Unknown UDP message type: {msg_type:#04x}")

    except (UnicodeDecodeError, IndexError, struct.error) as e:
        raise ValueError(f"Error parsing UDP payload for type {msg_type:#04x}: {e}")

    logging.debug(f"Parsed UDP msg: Type={TYPE_NAMES.get(msg_type, 'UNKNOWN')}({msg_type:#04x}), ID={msg_id}, Fields={fields}")
    return msg_type, msg_id, fields

def format_udp_message(msg_type, msg_id, **fields):
    """Formats a UDP message for sending."""

    # --- Special handling for CONFIRM ---
    if msg_type == TYPE_CONFIRM:
        try:
            # CONFIRM format is just: Type (0x00) + RefID (2 bytes)
            return bytes([TYPE_CONFIRM]) + struct.pack('>H', fields['ref_msg_id'])
        except KeyError:
             raise ValueError("Missing 'ref_msg_id' field for CONFIRM")
        except struct.error:
             raise ValueError("Invalid 'ref_msg_id' value for CONFIRM")
    # --- End Special handling for CONFIRM ---

    # --- Standard handling for other types ---
    try:
        header = struct.pack('>BH', msg_type, msg_id) # Standard Header
        payload = b''

        if msg_type == TYPE_REPLY:
            result_byte = b'\x01' if fields['result'] else b'\x00'
            ref_id_bytes = struct.pack('>H', fields['ref_msg_id'])
            content_bytes = fields['message_content'].encode('ascii') + b'\x00'
            payload = result_byte + ref_id_bytes + content_bytes
        # No AUTH/JOIN formatting needed for server
        elif msg_type == TYPE_MSG or msg_type == TYPE_ERR:
            display_name_bytes = fields['display_name'].encode('ascii') + b'\0'
            content_bytes = fields['message_content'].encode('ascii') + b'\x00'
            payload = display_name_bytes + content_bytes
        elif msg_type == TYPE_BYE:
            display_name_bytes = fields['display_name'].encode('ascii') + b'\0'
            payload = display_name_bytes
        elif msg_type == TYPE_PING:
            payload = b'' # No payload
        else:
            # Should not happen if called correctly, CONFIRM handled above
            raise ValueError(f"Cannot format unknown/unsupported server UDP type: {msg_type:#04x}")

        return header + payload

    except KeyError as e:
        raise ValueError(f"Missing field for UDP type {msg_type:#04x}: {e}")
    except UnicodeEncodeError as e:
        raise ValueError(f"Invalid characters for ASCII encoding: {e}")
    except struct.error as e:
        raise ValueError(f"Struct packing error for UDP type {msg_type:#04x}: {e}")

async def send_udp_reliable(client_key, transport, remote_addr, msg_type, msg_id, **fields):
    """Sends a UDP message and sets up confirmation handling."""
    async with clients_lock:
        client_info = clients.get(client_key)
        if not client_info:
            logging.warning(f"Attempted to send reliable UDP to non-existent client {client_key}")
            return

    if msg_type == TYPE_CONFIRM: # Confirms are not sent reliably
        try:
            message = format_udp_message(msg_type, msg_id, **fields)
            logging.debug(f"UDP SEND (unreliable) to {remote_addr}: {TYPE_NAMES.get(msg_type, 'UNKNOWN')}({msg_type:#04x}) ID={msg_id} RefID={fields.get('ref_msg_id', 'N/A')}")
            transport.sendto(message, remote_addr)
        except (ValueError, OSError) as e:
            logging.error(f"Error formatting/sending UDP CONFIRM to {remote_addr}: {e}")
        return

    # --- Reliable send logic ---
    try:
        message = format_udp_message(msg_type, msg_id, **fields)
    except ValueError as e:
        logging.error(f"Error formatting UDP message type {msg_type:#04x} for {remote_addr}: {e}")
        return

    confirm_key = (client_key, msg_id)

    async def resend_task(current_retries):
        nonlocal message # Need to access outer scope message
        while current_retries > 0:
            await asyncio.sleep(DEFAULT_TIMEOUT_MS / 1000.0)

            async with udp_confirms_lock:
                pending_info = udp_pending_confirms.get(confirm_key)
            if not pending_info: # Confirmed meanwhile or removed
                 logging.debug(f"Resend task for {confirm_key}: No longer pending.")
                 return

            async with clients_lock: # Check if client is still connected
                client_exists = client_key in clients
            if not client_exists:
                logging.warning(f"Resend task for {confirm_key}: Client disconnected.")
                async with udp_confirms_lock:
                    udp_pending_confirms.pop(confirm_key, None) # Clean up pending confirm
                return

            if server_shutdown_event.is_set(): # Check if server is shutting down
                logging.info(f"Resend task for {confirm_key}: Server shutting down.")
                async with udp_confirms_lock:
                    udp_pending_confirms.pop(confirm_key, None)
                return

            current_retries -= 1
            async with udp_confirms_lock: # Update retries left safely
                if confirm_key in udp_pending_confirms: # Re-check in case removed between client check and now
                   udp_pending_confirms[confirm_key]['retries_left'] = current_retries
                else:
                   logging.debug(f"Resend task for {confirm_key}: Removed before retry update.")
                   return # Already confirmed or removed

            logging.warning(f"UDP RESEND ({DEFAULT_RETRIES - current_retries}/{DEFAULT_RETRIES}) to {remote_addr}: {TYPE_NAMES.get(msg_type, 'UNKNOWN')}({msg_type:#04x}) ID={msg_id}")
            try:
                transport.sendto(message, remote_addr)
            except OSError as e:
                 logging.error(f"OSError on resend to {remote_addr}: {e}. Stopping retries.")
                 async with udp_confirms_lock:
                     udp_pending_confirms.pop(confirm_key, None)
                 # Consider disconnecting client here?
                 await disconnect_client(client_key, "Network error during resend")
                 return


        # If loop finishes, retries exhausted
        async with udp_confirms_lock:
            was_pending = confirm_key in udp_pending_confirms
            if was_pending:
                 udp_pending_confirms.pop(confirm_key, None)

        if was_pending: # Only log error and disconnect if it wasn't confirmed/removed
            logging.error(f"UDP TIMEOUT for {remote_addr}: No CONFIRM received for {TYPE_NAMES.get(msg_type, 'UNKNOWN')}({msg_type:#04x}) ID={msg_id} after {DEFAULT_RETRIES} retries.")
            # Terminate connection on timeout
            await disconnect_client(client_key, "Timeout waiting for CONFIRM")

    # --- Start the process ---
    retries = DEFAULT_RETRIES
    task = asyncio.create_task(resend_task(retries))
    async with udp_confirms_lock:
        udp_pending_confirms[confirm_key] = {
            'message': message,
            'retries_left': retries,
            'task': task,
            'send_time': time.monotonic()
        }
    logging.debug(f"UDP SEND (reliable) to {remote_addr}: {TYPE_NAMES.get(msg_type, 'UNKNOWN')}({msg_type:#04x}) ID={msg_id}")
    try:
        transport.sendto(message, remote_addr)
    except OSError as e:
        logging.error(f"OSError on initial send to {remote_addr}: {e}")
        task.cancel()
        async with udp_confirms_lock:
            udp_pending_confirms.pop(confirm_key, None)
        await disconnect_client(client_key, "Network error during send")


def parse_tcp_message(line):
    """Parses a TCP message line, returns (command, params) or raises ValueError."""
    line = line.strip()
    if not line:
        raise ValueError("Empty TCP message")

    parts = line.split(' ', 1)
    command = parts[0].upper()
    params = {}

    logging.debug(f"Parsing TCP line: '{line}'")

    try:
        if command == "AUTH" and len(parts) == 2:
            rest = parts[1]
            # AUTH {Username} AS {DisplayName} USING {Secret}
            auth_parts = rest.split(' AS ', 1)
            if len(auth_parts) != 2: raise ValueError("AUTH format error: Missing 'AS'")
            params['username'] = auth_parts[0]
            display_secret_parts = auth_parts[1].split(' USING ', 1)
            if len(display_secret_parts) != 2: raise ValueError("AUTH format error: Missing 'USING'")
            params['display_name'] = display_secret_parts[0]
            params['secret'] = display_secret_parts[1]
        elif command == "JOIN" and len(parts) == 2:
            rest = parts[1]
            # JOIN {ChannelID} AS {DisplayName}
            join_parts = rest.split(' AS ', 1)
            if len(join_parts) != 2: raise ValueError("JOIN format error: Missing 'AS'")
            params['channel_id'] = join_parts[0]
            params['display_name'] = join_parts[1] # Client sends this, server should use its known name
        elif command == "MSG" and len(parts) == 2:
            rest = parts[1]
            # MSG FROM {DisplayName} IS {MessageContent}
            if not rest.startswith("FROM "): raise ValueError("MSG format error: Missing 'FROM'")
            from_is_parts = rest[5:].split(' IS ', 1)
            if len(from_is_parts) != 2: raise ValueError("MSG format error: Missing 'IS'")
            params['display_name'] = from_is_parts[0] # Client sends this, server should use its known name
            params['message_content'] = from_is_parts[1]
        elif command == "BYE" and len(parts) == 2:
            rest = parts[1]
            # BYE FROM {DisplayName}
            if not rest.startswith("FROM "): raise ValueError("BYE format error: Missing 'FROM'")
            params['display_name'] = rest[5:] # Client sends this, server should use its known name
        elif command == "REPLY": # Server shouldn't receive REPLY
            raise ValueError("Server received unexpected REPLY message")
        elif command == "ERR": # Server shouldn't receive ERR
             raise ValueError("Server received unexpected ERR message")
        else:
            raise ValueError(f"Unknown or malformed TCP command: '{line}'")

    except IndexError:
        raise ValueError(f"Malformed TCP message structure for command {command}")

    logging.debug(f"Parsed TCP msg: Command={command}, Params={params}")
    return command, params

def format_tcp_message(command, **params):
    """Formats a TCP message for sending."""
    command = command.upper()
    try:
        if command == "REPLY":
            result_str = "OK" if params['result'] else "NOK"
            return f"REPLY {result_str} IS {params['message_content']}\r\n".encode('ascii')
        elif command == "MSG" or command == "ERR":
            return f"{command} FROM {params['display_name']} IS {params['message_content']}\r\n".encode('ascii')
        elif command == "BYE": # Server doesn't send BYE this way (client initiates or ERR)
             raise NotImplementedError("Server does not send BYE requests")
        elif command == "AUTH": # Server doesn't send AUTH
             raise NotImplementedError("Server does not send AUTH")
        elif command == "JOIN": # Server doesn't send JOIN
            raise NotImplementedError("Server does not send JOIN")
        else:
            raise ValueError(f"Cannot format unknown TCP command: {command}")
    except KeyError as e:
        raise ValueError(f"Missing field for TCP command {command}: {e}")
    except UnicodeEncodeError as e:
        raise ValueError(f"Invalid characters for ASCII encoding: {e}")

async def send_tcp_message(writer, command, **params):
    """Sends a formatted TCP message."""
    peername = None
    try:
        peername = writer.get_extra_info('peername') # Get peername early for logging
        message = format_tcp_message(command, **params)
        logging.debug(f"TCP SEND to {peername}: {message.decode('ascii').strip()}")
        writer.write(message)
        await writer.drain()
    except (ValueError, OSError, ConnectionResetError) as e:
        logging.error(f"Error sending TCP message to {peername}: {e}")
        # Attempt to disconnect client if send fails
        if peername:
            client_key = get_client_key('tcp', peername)
            await disconnect_client(client_key, f"Network error during send: {e}") # disconnect_client uses locks

async def broadcast_message(sender_key, channel_id, message_content, is_server_message=False, sender_display_name_override=None):
    """Sends a message to all clients in a channel, except the sender."""
    sender_info = None
    if sender_key:
        async with clients_lock:
            sender_info = clients.get(sender_key)

    display_name = "Server"
    if not is_server_message:
        if sender_info:
            display_name = sender_info['display_name']
        else:
             # Could happen if sender disconnected just before broadcast
             logging.warning(f"Broadcast requested for sender {sender_key} who is no longer connected.")
             # Use a default or potentially the override if provided
             display_name = sender_display_name_override if sender_display_name_override else f"Unknown_{sender_key}"

    if sender_display_name_override:
        display_name = sender_display_name_override

    recipients = []
    async with channels_lock:
        if channel_id in channels:
            recipients = list(channels[channel_id]) # Get copy of recipients under lock
        else:
            logging.warning(f"Broadcast requested for non-existent channel {channel_id}")
            return

    logging.info(f"Broadcasting to channel '{channel_id}' ({len(recipients)} recipients) from '{display_name}': {message_content[:50]}...")

    for client_key in recipients:
        # Don't send message back to original sender unless it's a server message
        if not is_server_message and client_key == sender_key:
            continue

        # Get recipient info under lock, release lock before sending
        recipient_writer = None
        recipient_protocol = None
        recipient_addr = None
        recipient_transport_type = None
        recipient_last_msg_id = 0

        async with clients_lock:
            recipient_info = clients.get(client_key)
            if not recipient_info:
                logging.warning(f"Broadcast: Client {client_key} disappeared before sending.")
                # Clean up from channel (needs channel_lock again, might be complex here)
                # Consider periodic cleanup task instead of doing it in broadcast.
                continue

            recipient_transport_type = recipient_info['transport_type']
            if recipient_transport_type == 'tcp':
                recipient_writer = recipient_info.get('writer')
            elif recipient_transport_type == 'udp':
                 recipient_protocol = recipient_info.get('protocol')
                 recipient_addr = recipient_info.get('addr')
                 # Atomically increment message ID under lock
                 recipient_info['last_msg_id_sent'] += 1
                 recipient_last_msg_id = recipient_info['last_msg_id_sent']

        # --- Send message (outside locks) ---
        if recipient_transport_type == 'tcp':
            if recipient_writer and not recipient_writer.is_closing():
                # Create task to avoid blocking broadcast loop on slow clients
                 asyncio.create_task(send_tcp_message(recipient_writer, "MSG",
                                       display_name=display_name,
                                       message_content=message_content))
            else:
                logging.warning(f"Broadcast: TCP Client {client_key} has no writer or writer is closing.")
        elif recipient_transport_type == 'udp':
             if recipient_protocol and recipient_protocol.transport and recipient_addr:
                # UDP requires reliable sending - create task
                 asyncio.create_task(send_udp_reliable(client_key, recipient_protocol.transport, recipient_addr,
                                        TYPE_MSG, recipient_last_msg_id, # Use the incremented ID
                                        display_name=display_name,
                                        message_content=message_content))
             else:
                 logging.warning(f"Broadcast: UDP Client {client_key} missing protocol/transport/addr.")


async def disconnect_client(client_key, reason="Connection closed"):
    """Handles disconnection for both TCP and UDP clients, using locks."""
    client_info = None
    async with clients_lock:
        if client_key in clients:
            client_info = clients.pop(client_key)
        else:
            return # Already disconnected

    # Now client_info holds the popped data, and the client is removed from the main dict

    transport_type = client_info['transport_type']
    addr = client_info['addr']
    display_name = client_info.get('display_name', str(addr))
    current_channel = client_info.get('channel')
    writer = client_info.get('writer') # TCP
    protocol_instance = client_info.get('protocol') # UDP
    ping_task = client_info.get('ping_task') # UDP

    logging.info(f"Disconnecting {transport_type.upper()} client {display_name}@{addr}: {reason}")

    # Remove from channel (needs channel lock)
    channel_removed = False
    async with channels_lock:
        if current_channel and current_channel in channels:
            channels[current_channel].discard(client_key)
            if not channels[current_channel]: # Remove empty channel
                del channels[current_channel]
                channel_removed = True

    if channel_removed:
         logging.info(f"Channel '{current_channel}' is now empty and removed.")
    # Optional: Notify others in the channel (needs another broadcast call)
    # Be careful about potential lock contention if done here.
    # Consider if leave messages are truly required by spec.

    # Clean up transport/sockets
    if transport_type == 'tcp':
        if writer and not writer.is_closing():
            try:
                writer.close()
                # wait_closed can take time, do it outside locks if possible
                await writer.wait_closed()
            except Exception as e:
                logging.warning(f"Exception closing TCP writer for {addr}: {e}")
    elif transport_type == 'udp':
        # Cancel pending confirms for this client (needs confirms lock)
        async with udp_confirms_lock:
            confirm_keys_to_remove = [ck for ck in udp_pending_confirms if ck[0] == client_key]
            tasks_to_cancel = []
            for ck in confirm_keys_to_remove:
                 pending = udp_pending_confirms.pop(ck, None)
                 if pending and pending.get('task'):
                     tasks_to_cancel.append(pending['task'])
                     #pending['task'].cancel() # Cancel outside lock?
            # Cancel tasks after releasing lock
            for task in tasks_to_cancel:
                task.cancel()
                logging.debug(f"Cancelled pending confirm task for {ck}")


        # Stop ping task if running
        if ping_task:
            ping_task.cancel()

        # Remove from UDP listener map IF it was a dedicated listener
        if protocol_instance and protocol_instance.transport:
            listener_socket = protocol_instance.transport.get_extra_info('socket')
            # Needs listeners lock
            async with udp_listeners_lock:
                 # Check if it's still the same protocol instance (could be closed/reassigned?)
                 if listener_socket in udp_listeners and udp_listeners[listener_socket] == protocol_instance:
                      # Only close if it's a dynamic socket, not the main one
                      main_listener_sock = next((s for s, p in udp_listeners.items() if p.is_main_listener), None)
                      if listener_socket != main_listener_sock:
                           logging.debug(f"Closing dynamic UDP socket {listener_socket.getsockname()} for {addr}")
                           protocol_instance.transport.close() # Close transport
                           udp_listeners.pop(listener_socket, None) # Remove from map
                      else:
                           logging.debug(f"Not closing main UDP listener socket for disconnected client {addr}")


# --- TCP Client Handler ---
async def handle_tcp_client(reader, writer):
    """Coroutine to handle a single TCP client connection."""
    peername = writer.get_extra_info('peername')
    client_key = get_client_key('tcp', peername)
    logging.info(f"TCP connection from {peername}")

    # Add client info under lock
    async with clients_lock:
        clients[client_key] = {
            'transport_type': 'tcp',
            'addr': peername,
            'reader': reader,
            'writer': writer,
            'authenticated': False,
            'username': None,
            'display_name': f"TCP_{peername[0]}:{peername[1]}", # Default
            'channel': None,
            'join_time': time.monotonic()
        }

    try:
        while not server_shutdown_event.is_set():
            try:
                # Read data
                data = await reader.readline()
                if not data:
                    await disconnect_client(client_key, "Connection closed by peer")
                    break # Client disconnected

                line = data.decode('ascii').strip()
                if not line: continue # Ignore empty lines

                command, params = parse_tcp_message(line)

                # --- Process Command (acquire lock only when needed) ---
                # Re-fetch client info under lock to ensure consistency for state checks/updates
                async with clients_lock:
                     client_info = clients.get(client_key)
                     if not client_info: break # Disconnected by another task while reading

                     is_authenticated = client_info['authenticated']
                     current_channel = client_info['channel']
                     current_display_name = client_info['display_name']

                # --- State Machine Logic ---
                if not is_authenticated:
                    if command == "AUTH":
                        username = params['username']
                        secret = params['secret']
                        display_name = params['display_name'] # Use client provided name on AUTH

                        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == secret:
                            logging.info(f"TCP Auth success for {username}@{peername} as '{display_name}'")
                            # Update state under lock
                            new_channel = 'default'
                            async with clients_lock:
                                # Re-check client still exists before modifying
                                if client_key in clients:
                                    clients[client_key]['authenticated'] = True
                                    clients[client_key]['username'] = username
                                    clients[client_key]['display_name'] = display_name
                                    clients[client_key]['channel'] = new_channel
                                else: continue # Disconnected while processing

                            # Add to channel under lock
                            async with channels_lock:
                                channels[new_channel].add(client_key)

                            # Send reply (outside lock)
                            await send_tcp_message(writer, "REPLY", result=True, message_content="Auth success.") # XXX
                            # Broadcast join message (outside lock)
                            await broadcast_message(client_key, new_channel, f"{display_name} joined {new_channel}.", is_server_message=True, sender_display_name_override="Server") # XXX
                        else:
                            logging.warning(f"TCP Auth failed for {username}@{peername}")
                            await send_tcp_message(writer, "REPLY", result=False, message_content="Auth failed.") # XXX
                            # --- CHANGE: Allow retry ---
                            # Do not disconnect, just send failure reply.
                            # The loop will continue, allowing another AUTH attempt.
                            # --- End CHANGE ---
                    else:
                         logging.warning(f"TCP Client {peername} sent {command} before AUTH.")
                         await send_tcp_message(writer, "ERR", display_name="Server", message_content="Authentication required.")
                         await disconnect_client(client_key, "Sent command before authentication")
                         break # Disconnect if sending other commands before AUTH
                else: # Authenticated state
                    if command == "AUTH":
                         logging.warning(f"TCP Client {peername} sent AUTH while already authenticated.")
                         await send_tcp_message(writer, "ERR", display_name="Server", message_content="Already authenticated.")
                         # Don't disconnect, just send error.
                    elif command == "JOIN":
                        new_channel_id = params['channel_id']
                        old_channel = None
                        # Update state under lock
                        async with clients_lock:
                            # Re-check client still exists
                            if client_key in clients:
                                old_channel = clients[client_key]['channel']
                                clients[client_key]['channel'] = new_channel_id
                            else: continue # Disconnected

                        # Update channels under lock
                        channel_removed = False
                        async with channels_lock:
                            if old_channel: # Remove from old channel if existed
                                channels[old_channel].discard(client_key)
                                if not channels[old_channel]:
                                    del channels[old_channel]
                                    channel_removed = True
                            channels[new_channel_id].add(client_key) # Add to new channel

                        logging.info(f"TCP Client {current_display_name}@{peername} joined channel '{new_channel_id}'")
                        if channel_removed:
                             logging.info(f"Channel '{old_channel}' is now empty and removed.")
                        # Optional: Notify old channel (needs another broadcast)

                        # Send reply (outside lock)
                        await send_tcp_message(writer, "REPLY", result=True, message_content="Join success.") # XXX
                        # Broadcast join message (outside lock)
                        await broadcast_message(client_key, new_channel_id, f"{current_display_name} joined {new_channel_id}.", is_server_message=True, sender_display_name_override="Server") # XXX

                    elif command == "MSG":
                        sender_name_in_msg = params['display_name']
                        message_content = params['message_content']
                        if not current_channel:
                             logging.warning(f"TCP Client {peername} tried to send MSG but is not in a channel.")
                             await send_tcp_message(writer, "ERR", display_name="Server", message_content="Not currently in a channel.")
                        else:
                            logging.info(f"TCP MSG from {sender_name_in_msg} (reported by client, server knows as {current_display_name})@{peername} in '{current_channel}': {message_content[:50]}...")
                            await broadcast_message(client_key, current_channel, message_content, sender_display_name_override=sender_name_in_msg)

                    elif command == "BYE":
                        logging.info(f"TCP Client {current_display_name}@{peername} sent BYE.")
                        await disconnect_client(client_key, "Client sent BYE")
                        break # Exit loop after BYE

            except (ValueError, UnicodeDecodeError) as e:
                logging.error(f"TCP Protocol error from {peername}: {e}")
                # Try to send ERR (best effort)
                async with clients_lock: # Check if writer still exists
                    if client_key in clients:
                        err_writer = clients[client_key].get('writer')
                        if err_writer and not err_writer.is_closing():
                           try:
                               # Send ERR outside lock to avoid holding it during I/O
                               await send_tcp_message(err_writer, "ERR", display_name="Server", message_content=f"Protocol error: {e}")
                           except Exception: pass # Ignore send error if client already disconnected
                await disconnect_client(client_key, f"Protocol error: {e}")
                break
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                await disconnect_client(client_key, "Connection lost")
                break
            except asyncio.CancelledError:
                logging.info(f"TCP handler for {peername} cancelled.")
                # disconnect_client should be called by shutdown logic
                break
            except Exception as e:
                logging.exception(f"Unexpected error handling TCP client {peername}: {e}")
                await disconnect_client(client_key, f"Internal server error: {e}")
                break

    finally:
        # Final cleanup attempt if not already done by explicit calls
        await disconnect_client(client_key, "Handler finished")


# --- UDP Protocol Handler ---
class UdpProtocol(asyncio.DatagramProtocol):
    """Handles incoming UDP datagrams for BOTH main listener and dynamic ports."""
    def __init__(self, server_loop, is_main=False):
        self.loop = server_loop
        self.transport = None
        self.is_main_listener = is_main
        self.listen_addr = None # Set in connection_made

    def connection_made(self, transport):
        self.transport = transport
        self.listen_addr = transport.get_extra_info('sockname')
        # Add listener under lock
        asyncio.create_task(self._register_listener()) # Use task to avoid blocking event loop with lock
        logging.info(f"UDP {'Main ' if self.is_main_listener else 'Dynamic '}Listener started on {self.listen_addr}")

    async def _register_listener(self):
        """Helper to register listener under lock."""
        async with udp_listeners_lock:
            udp_listeners[self.transport.get_extra_info('socket')] = self

    def datagram_received(self, data, addr):
        """Handles received datagrams on the socket this instance listens on."""
        # Offload processing to an async task to avoid blocking the datagram_received callback
        asyncio.create_task(self.process_datagram(data, addr))

    async def process_datagram(self, data, addr):
        """Async processing of a received datagram."""
        logging.debug(f"UDP RECV from {addr} on {self.listen_addr} ({len(data)} bytes)")
        client_key = get_client_key('udp', addr)

        try:
            msg_type, msg_id, fields = parse_udp_message(data)

            # --- Duplicate Message Check (needs client lock) ---
            is_duplicate = False
            if msg_type != TYPE_CONFIRM:
                async with clients_lock:
                    client_info = clients.get(client_key)
                    if client_info:
                        received_ids = client_info.get('received_msg_ids')
                        if received_ids is not None: # Check if the deque exists
                           if msg_id in received_ids:
                               is_duplicate = True
                           else:
                               received_ids.append(msg_id) # Add to received set

                if is_duplicate:
                     logging.warning(f"UDP Duplicate message {msg_id} from {addr}. Sending CONFIRM.")
                     self.send_confirm(addr, msg_id) # Send confirm even for duplicates
                     return # Discard duplicate

            # --- Handle CONFIRM messages (needs confirms lock) ---
            if msg_type == TYPE_CONFIRM:
                ref_msg_id = fields['ref_msg_id']
                confirm_key = (client_key, ref_msg_id)
                task_to_cancel = None
                async with udp_confirms_lock:
                    pending = udp_pending_confirms.pop(confirm_key, None)
                    if pending:
                        task_to_cancel = pending.get('task')
                    else:
                        logging.warning(f"UDP Received unexpected CONFIRM from {addr} for msg ID {ref_msg_id} (maybe late?)")
                # Cancel task outside lock
                if task_to_cancel:
                    task_to_cancel.cancel()
                    logging.debug(f"UDP CONFIRM received from {addr} for msg ID {ref_msg_id}")
                return # No further processing for CONFIRM

            # --- Send CONFIRM for non-CONFIRM messages (sent unreliably) ---
            self.send_confirm(addr, msg_id)

            # --- State Machine Logic (needs client lock for reads/writes) ---
            client_info = None
            is_authenticated = False
            current_channel = None
            current_display_name = None
            last_msg_id_sent = 0

            async with clients_lock:
                 client_info_check = clients.get(client_key)
                 if client_info_check:
                      client_info = client_info_check # Keep reference for later use outside lock if needed
                      is_authenticated = client_info['authenticated']
                      current_channel = client_info['channel']
                      current_display_name = client_info['display_name']
                      last_msg_id_sent = client_info['last_msg_id_sent']

            # --- Process based on state ---
            if not client_info: # New client or message on main listener
                 if msg_type == TYPE_AUTH:
                      if not self.is_main_listener:
                           logging.warning(f"UDP Received AUTH on unexpected dynamic port {self.listen_addr} from {addr}. Ignoring.")
                           # Maybe send ERR back unreliably?
                           await self.send_err(addr, 0, "AUTH received on wrong port.", is_reliable=False) # Send unreliably
                           return

                      logging.info(f"UDP New client attempt from {addr} with AUTH msg ID {msg_id}")
                      # Handle AUTH - create dynamic listener for this client (this method handles locks internally)
                      await self.handle_new_udp_client(addr, msg_type, msg_id, fields)
                 else:
                      # Any other message from an unknown client is an error
                      logging.warning(f"UDP Received non-AUTH message type {msg_type:#04x} from unknown client {addr}. Ignoring.")
                      # Send ERR unreliably as we don't know the client
                      await self.send_err(addr, 0, "Must send AUTH first.", is_reliable=False)
            else: # Existing client
                if self.is_main_listener:
                     logging.warning(f"UDP Received message type {msg_type:#04x} from known client {addr} on MAIN listener. Should be on dynamic port {client_info.get('listen_addr')}. Ignoring.")
                     # Send ERR unreliably on main listener
                     await self.send_err(addr, 0, "Use your dedicated port for messages after AUTH.", is_reliable=False)
                     return

                # Message received on the correct dynamic listener for this client
                if not is_authenticated:
                    # Should not happen if AUTH was processed correctly and state is consistent
                    logging.error(f"UDP Client {addr} is known but not marked authenticated. State error.")
                    await self.send_err(addr, 0, "Internal server state error.", is_reliable=True) # Send ERR reliably
                    await disconnect_client(client_key, "Internal server state error")
                    return

                # --- Authenticated State ---
                if msg_type == TYPE_AUTH:
                     logging.warning(f"UDP Client {addr} sent AUTH while already authenticated.")
                     await self.send_err(addr, msg_id, "Already authenticated.", is_reliable=True)
                elif msg_type == TYPE_JOIN:
                    new_channel_id = fields['channel_id']
                    old_channel = None

                    # Update client channel under lock
                    async with clients_lock:
                        if client_key in clients:
                            old_channel = clients[client_key]['channel']
                            clients[client_key]['channel'] = new_channel_id
                        else: return # Client disconnected

                    # Update channels sets under lock
                    channel_removed = False
                    async with channels_lock:
                        if old_channel:
                            channels[old_channel].discard(client_key)
                            if not channels[old_channel]:
                                del channels[old_channel]
                                channel_removed = True
                        channels[new_channel_id].add(client_key)

                    logging.info(f"UDP Client {current_display_name}@{addr} joined channel '{new_channel_id}'")
                    if channel_removed:
                        logging.info(f"Channel '{old_channel}' is now empty and removed.")

                    # Send REPLY (reliably) - needs to increment msg ID atomically
                    reply_msg_id = 0
                    async with clients_lock:
                         if client_key in clients: # Check again before incrementing
                             clients[client_key]['last_msg_id_sent'] += 1
                             reply_msg_id = clients[client_key]['last_msg_id_sent']
                         else: return # Disconnected

                    await send_udp_reliable(client_key, self.transport, addr,
                                                            TYPE_REPLY, reply_msg_id,
                                                            result=True, ref_msg_id=msg_id,
                                                            message_content="Join success.")
                    # Broadcast MSG (reliably to UDP clients)
                    await broadcast_message(client_key, new_channel_id, f"{current_display_name} joined {new_channel_id}.", is_server_message=True, sender_display_name_override="Server")

                elif msg_type == TYPE_MSG:
                    message_content = fields['message_content']
                    if not current_channel:
                        logging.warning(f"UDP Client {addr} tried to send MSG but not in channel.")
                        await self.send_err(addr, msg_id, "Not currently in a channel.", is_reliable=True)
                    else:
                         logging.info(f"UDP MSG from {current_display_name}@{addr} in '{current_channel}': {message_content[:50]}...")
                         await broadcast_message(client_key, current_channel, message_content, sender_display_name_override=current_display_name)

                elif msg_type == TYPE_BYE:
                     logging.info(f"UDP Client {current_display_name}@{addr} sent BYE.")
                     # Confirm was already sent
                     await disconnect_client(client_key, "Client sent BYE")

                elif msg_type == TYPE_PING: # Client should not send PING
                    logging.warning(f"UDP Client {addr} sent unexpected PING message.")
                    await self.send_err(addr, msg_id, "Clients should not send PING.", is_reliable=True)

                elif msg_type == TYPE_ERR: # Client should not send ERR
                    logging.warning(f"UDP Client {addr} sent unexpected ERR message: {fields.get('message_content', 'N/A')}")
                    # Specification implies ERR leads to termination.
                    await disconnect_client(client_key, f"Client sent ERR: {fields.get('message_content', 'N/A')}")

                else: # Should be handled by parser, but safety check
                    logging.warning(f"UDP Unhandled message type {msg_type:#04x} from authenticated client {addr}.")
                    await self.send_err(addr, msg_id, f"Unhandled message type {msg_type:#04x}", is_reliable=True)


        except ValueError as e:
            logging.error(f"UDP Protocol parse error from {addr}: {e}. Data: {data.hex()}")
            # Try to send ERR. If client is known and on dynamic port, send reliably. Otherwise unreliably.
            is_known = False
            async with clients_lock:
                is_known = client_key in clients

            if is_known and not self.is_main_listener:
                 await self.send_err(addr, 0, f"Protocol parse error: {e}", is_reliable=True)
                 await disconnect_client(client_key, f"Protocol parse error: {e}")
            else:
                 await self.send_err(addr, 0, f"Protocol parse error: {e}", is_reliable=False)
                 # Cannot reliably disconnect if unknown or on main listener

        except Exception as e:
            logging.exception(f"Unexpected error handling UDP datagram from {addr}: {e}")
            # Attempt to disconnect if client is known
            async with clients_lock:
                 is_known = client_key in clients
            if is_known:
                 await disconnect_client(client_key, f"Internal server error: {e}")

    def send_confirm(self, remote_addr, ref_msg_id):
        """Sends a CONFIRM message (unreliably)."""
        # Confirms use message ID 0 as per spec example diagram
        try:
            # CONFIRM must be sent from the socket the original message arrived on.
            logging.debug(f"UDP SEND CONFIRM to {remote_addr} for RefID={ref_msg_id}")
            msg = format_udp_message(TYPE_CONFIRM, 0, ref_msg_id=ref_msg_id)
            if self.transport: # Ensure transport is still available
                 self.transport.sendto(msg, remote_addr)
            else:
                 logging.warning(f"Cannot send CONFIRM to {remote_addr}: Transport closed.")
        except (ValueError, OSError) as e:
            logging.error(f"Error sending UDP CONFIRM to {remote_addr}: {e}")

    async def send_err(self, remote_addr, ref_msg_id_or_zero, message_content, is_reliable=True):
         """Sends an ERR message. Reliably if possible/requested, otherwise unreliably."""
         client_key = get_client_key('udp', remote_addr)
         client_info = None
         should_send_reliably = is_reliable and not self.is_main_listener # Can only send reliably on dynamic socket

         if should_send_reliably:
             err_msg_id = 0
             async with clients_lock:
                 client_info = clients.get(client_key)
                 if client_info: # Send reliably via dynamic socket
                     client_info['last_msg_id_sent'] += 1
                     err_msg_id = client_info['last_msg_id_sent']
                 else:
                      should_send_reliably = False # Cannot send reliably if client is gone

             if should_send_reliably:
                 logging.error(f"Sending reliable ERR to {remote_addr} (MsgID {err_msg_id}): {message_content}")
                 # Use self.transport as this method is called on the protocol instance
                 await send_udp_reliable(client_key, self.transport, remote_addr,
                                                        TYPE_ERR, err_msg_id,
                                                        display_name="Server",
                                                        message_content=message_content)
             else:
                 # Fallback to unreliable if client disappeared before sending
                  try:
                     err_msg_id = 0 # Use 0 for unreliable ERR
                     logging.error(f"Sending unreliable ERR to {remote_addr} (RefID {ref_msg_id_or_zero}): {message_content}")
                     msg = format_udp_message(TYPE_ERR, err_msg_id, display_name="Server", message_content=message_content)
                     if self.transport:
                         self.transport.sendto(msg, remote_addr)
                  except (ValueError, OSError) as e:
                      logging.error(f"Error sending fallback UDP ERR to {remote_addr}: {e}")

         else: # Send unreliably
             try:
                  err_msg_id = 0 # Use 0 for unreliable ERR
                  logging.error(f"Sending unreliable ERR to {remote_addr} (RefID {ref_msg_id_or_zero}): {message_content}")
                  msg = format_udp_message(TYPE_ERR, err_msg_id, display_name="Server", message_content=message_content)
                  if self.transport:
                      self.transport.sendto(msg, remote_addr)
             except (ValueError, OSError) as e:
                  logging.error(f"Error sending unreliable UDP ERR to {remote_addr}: {e}")

    async def handle_new_udp_client(self, remote_addr, auth_msg_type, auth_msg_id, auth_fields):
        """Authenticates and sets up a dedicated UDP listener for a new client."""
        # CONFIRM for AUTH was already sent by datagram_received on the main listener socket.
        client_key = get_client_key('udp', remote_addr)

        username = auth_fields['username']
        secret = auth_fields['secret']
        display_name = auth_fields['display_name'] # Use client provided name on AUTH

        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == secret:
             logging.info(f"UDP Auth success for {username}@{remote_addr} as '{display_name}'. Creating dynamic socket.")

             dynamic_transport = None
             dynamic_protocol = None
             dynamic_listen_addr = None
             # --- Create dedicated listener ---
             try:
                 loop = asyncio.get_running_loop()
                 dynamic_transport, dynamic_protocol = await loop.create_datagram_endpoint(
                     lambda: UdpProtocol(loop, is_main=False), # New protocol instance for this client
                     local_addr=(self.listen_addr[0], 0), # Bind to same IP, OS chooses port
                     family=socket.AF_INET)
                 dynamic_listen_addr = dynamic_transport.get_extra_info('sockname')
                 logging.info(f"UDP Dynamic listener for {remote_addr} created on {dynamic_listen_addr}")

             except OSError as e:
                 logging.error(f"Failed to create dynamic UDP socket for {remote_addr}: {e}")
                 # Send negative REPLY from main listener (unreliably)
                 self.send_reply(remote_addr, auth_msg_id, False, "Server error creating dedicated socket.")
                 return

             # --- Store client state (under locks) ---
             new_channel = 'default'
             client_info_data = {
                 'transport_type': 'udp',
                 'addr': remote_addr, # Client's address
                 'protocol': dynamic_protocol, # The protocol instance handling the dynamic socket
                 'listen_addr': dynamic_listen_addr, # Server's dynamic listen address
                 'authenticated': True,
                 'username': username,
                 'display_name': display_name,
                 'channel': new_channel,
                 'last_msg_id_sent': 0, # Server's outgoing message ID counter for this client
                 'received_msg_ids': deque(maxlen=100), # Track last 100 received IDs
                 'join_time': time.monotonic(),
                 'ping_task': None
             }
             async with clients_lock:
                 clients[client_key] = client_info_data
             async with channels_lock:
                 channels[new_channel].add(client_key)

             # --- Send positive REPLY (from dynamic socket, reliably) ---
             # Needs atomic increment
             reply_msg_id = 0
             async with clients_lock:
                 if client_key in clients: # Check client still exists
                     clients[client_key]['last_msg_id_sent'] += 1
                     reply_msg_id = clients[client_key]['last_msg_id_sent']
                 else: return # Disconnected before reply could be sent

             # Use the new dynamic transport/protocol to send
             await send_udp_reliable(client_key, dynamic_transport, remote_addr,
                                     TYPE_REPLY, reply_msg_id,
                                     result=True, ref_msg_id=auth_msg_id,
                                     message_content="Auth success.")

             # --- Broadcast join message (reliably to UDP clients) ---
             await broadcast_message(client_key, new_channel, f"{display_name} joined {new_channel}.", is_server_message=True, sender_display_name_override="Server")

             # --- Start PING task ---
             ping_task_obj = self.loop.create_task(self.ping_client(client_key))
             async with clients_lock: # Store ping task reference under lock
                 if client_key in clients:
                    clients[client_key]['ping_task'] = ping_task_obj

        else:
             logging.warning(f"UDP Auth failed for {username}@{remote_addr}")
             # Send negative REPLY (from main listener, unreliably, as no dynamic socket exists)
             self.send_reply(remote_addr, auth_msg_id, False, "Auth failed.")
             # Do not create client entry or dynamic socket

    def send_reply(self, remote_addr, ref_msg_id, result, message_content):
         """Sends a REPLY message (unreliably - used for failures before dynamic socket)."""
         # Use msg_id 0 for unreliably sent REPLY? Spec ambiguous.
         reply_msg_id = 0
         try:
             msg = format_udp_message(TYPE_REPLY, reply_msg_id,
                                      result=result, ref_msg_id=ref_msg_id,
                                      message_content=message_content)
             logging.debug(f"UDP SEND REPLY (unreliable) to {remote_addr} RefID={ref_msg_id} Result={result}")
             if self.transport:
                 self.transport.sendto(msg, remote_addr)
         except (ValueError, OSError) as e:
              logging.error(f"Error sending UDP REPLY to {remote_addr}: {e}")

    async def ping_client(self, client_key):
        """Periodically sends PING messages to a UDP client."""
        logging.debug(f"Starting PING task for {client_key}")
        while not server_shutdown_event.is_set():
             await asyncio.sleep(PING_INTERVAL_S)

             if server_shutdown_event.is_set(): break # Check again after sleep

             # Get client info under lock
             client_info = None
             protocol_instance = None
             udp_addr = None
             ping_msg_id = 0
             transport_to_use = None

             async with clients_lock:
                 client_info = clients.get(client_key)
                 if not client_info or client_info['transport_type'] != 'udp':
                      logging.debug(f"Stopping PING task for {client_key}: Client disconnected or changed type.")
                      break # Exit loop

                 protocol_instance = client_info.get('protocol')
                 udp_addr = client_info.get('addr')
                 # Increment message ID under lock
                 client_info['last_msg_id_sent'] += 1
                 ping_msg_id = client_info['last_msg_id_sent']
                 if protocol_instance:
                     transport_to_use = protocol_instance.transport

             # Send PING outside lock
             if transport_to_use and udp_addr:
                 logging.debug(f"Sending PING {ping_msg_id} to {client_key}")
                 # PING needs reliable sending (requires CONFIRM back)
                 await send_udp_reliable(client_key, transport_to_use, udp_addr,
                                         TYPE_PING, ping_msg_id)
             elif not transport_to_use:
                 logging.warning(f"Could not send PING to {client_key}: Transport missing/closed in protocol instance.")
                 break # Stop task if transport is gone
             else: # Should not happen if transport_to_use is None
                 logging.warning(f"Could not send PING to {client_key}: Missing transport or address.")
                 break

        logging.debug(f"PING task finished for {client_key}")


    def error_received(self, exc):
        # Handle lower-level socket errors (e.g., ICMP port unreachable)
        logging.error(f"UDP socket error on {self.listen_addr}: {exc}")
        if not self.is_main_listener:
            # Find client associated with this protocol instance (best effort without lock initially)
            # This is tricky as the protocol instance might be removed from client dict before error_received fires
            client_key_guess = next((ck for ck, ci in clients.items() if ci.get('protocol') == self), None)
            if client_key_guess:
                 logging.warning(f"Assuming UDP client {client_key_guess} disconnected due to socket error.")
                 # Disconnect client requires lock, run as task
                 asyncio.create_task(disconnect_client(client_key_guess, f"Socket error: {exc}"))
            else:
                 logging.error(f"UDP socket error on dynamic port {self.listen_addr}, but couldn't find associated client.")

    def connection_lost(self, exc):
        # Called when the transport is closed.
        logging.info(f"UDP {'Main ' if self.is_main_listener else 'Dynamic '}Listener on {self.listen_addr} closed.")
        if self.transport:
             listener_socket = self.transport.get_extra_info('socket')
             # Remove listener under lock
             asyncio.create_task(self._unregister_listener(listener_socket))

    async def _unregister_listener(self, sock):
        """Helper to unregister listener under lock."""
        async with udp_listeners_lock:
            udp_listeners.pop(sock, None)

# --- Signal Handling ---
async def shutdown(signal, loop):
    if server_shutdown_event.is_set(): return # Already shutting down
    logging.info(f"Received exit signal {signal.name}...")
    server_shutdown_event.set()

    # Close listening sockets first
    tasks = []
    if 'tcp_server' in globals() and tcp_server:
        logging.info("Closing TCP server...")
        tcp_server.close()
        tasks.append(loop.create_task(tcp_server.wait_closed()))

    # Close UDP listeners (needs lock)
    async with udp_listeners_lock:
        udp_listener_sockets = list(udp_listeners.keys()) # Copy keys
        for sock in udp_listener_sockets:
            proto_instance = udp_listeners.get(sock)
            if proto_instance and proto_instance.transport:
                logging.info(f"Closing UDP listener on {proto_instance.listen_addr}...")
                proto_instance.transport.close()
                # No wait_closed for datagram transports

    # Disconnect all clients gracefully (needs lock)
    async with clients_lock:
        client_keys = list(clients.keys()) # Get keys under lock

    # Disconnect outside lock to avoid holding it during disconnect logic
    disconnect_tasks = [disconnect_client(ck, "Server shutting down") for ck in client_keys]
    await asyncio.gather(*disconnect_tasks, return_exceptions=True)


    # Cancel pending confirms (needs lock)
    async with udp_confirms_lock:
        confirm_keys = list(udp_pending_confirms.keys())
        tasks_to_cancel = []
        for ck in confirm_keys:
            pending = udp_pending_confirms.pop(ck, None)
            if pending and pending.get('task'):
                tasks_to_cancel.append(pending['task'])
    # Cancel outside lock
    for task in tasks_to_cancel:
        task.cancel()

    # Wait for TCP server close tasks
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Allow time for remaining tasks to finish/cancel
    await asyncio.sleep(0.1) # Brief pause

    current_tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if current_tasks:
         logging.info(f"Cancelling {len(current_tasks)} outstanding tasks...")
         for task in current_tasks:
              task.cancel()
         await asyncio.gather(*current_tasks, return_exceptions=True)


    logging.info("Shutdown complete.")
    loop.stop()


# --- Main Execution ---
async def main(host, port):
    loop = asyncio.get_running_loop()

    # Add signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Use lambda to pass signal object to shutdown handler
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, loop)))

    logging.info(f"Starting server on {host}:{port}")
    logging.info(f"Config: UDP Timeout={DEFAULT_TIMEOUT_MS}ms, Retries={DEFAULT_RETRIES}, PING Interval={PING_INTERVAL_S}s")

    # Start TCP Server
    global tcp_server
    tcp_server = None
    try:
        tcp_server = await asyncio.start_server(
            handle_tcp_client, host, port, family=socket.AF_INET
        )
        addr = tcp_server.sockets[0].getsockname()
        logging.info(f'TCP Server listening on {addr}')
    except OSError as e:
         logging.error(f"Failed to start TCP server on {host}:{port}: {e}")
         return # Cannot continue without TCP server

    # Start Main UDP Listener
    udp_transport = None
    try:
        udp_transport, udp_protocol = await loop.create_datagram_endpoint(
            lambda: UdpProtocol(loop, is_main=True),
            local_addr=(host, port), family=socket.AF_INET)
        logging.info(f'Main UDP Listener active on {udp_transport.get_extra_info("sockname")}')
    except OSError as e:
        logging.error(f"Failed to start main UDP listener on {host}:{port}: {e}")
        logging.warning("Proceeding without UDP support.")
        # Optionally shutdown TCP server here if UDP is essential
        # tcp_server.close()
        # await tcp_server.wait_closed()
        # return

    # Keep servers running until shutdown event
    await server_shutdown_event.wait()

    # Final cleanup after loop stops (although shutdown should handle most)
    if tcp_server and tcp_server.is_serving():
        tcp_server.close()
    if udp_transport and not udp_transport.is_closing():
        udp_transport.close()
    logging.info("Main loop finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPK25-CHAT Server (TCP/UDP)")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                        help=f'Server port (default: {DEFAULT_PORT})')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Host address to bind to (default: 0.0.0.0)')
    args = parser.parse_args()

    try:
        asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
        # This should ideally be handled by the signal handler,
        # but can catch it here as a fallback.
        logging.info("KeyboardInterrupt caught in __main__.")
        # Event loop might already be stopped by shutdown.