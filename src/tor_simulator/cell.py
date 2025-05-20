CELL_SIZE = 512
MAX_PAYLOAD_SIZE = CELL_SIZE - 11
CMD_CREATE = 1
CMD_CREATED = 2
CMD_RELAY = 3
CMD_DESTROY = 4

RELAY_EXTEND = 1
RELAY_EXTENDED = 2
RELAY_DATA = 3
RELAY_END = 4

DUMMY = 255

# Creates a Tor cell
def create_cell(circ_id: int, command: int, payload: bytes) -> bytes:
    recognized = b'\x00\x00'
    digest = b'\x00\x00\x00\x00'
    length_bytes = len(payload).to_bytes(2, 'big')
    header = (circ_id.to_bytes(2, 'big') +
              command.to_bytes(1, 'big') +
              recognized + digest + length_bytes)
    cell = header + payload
    return cell.ljust(CELL_SIZE, b'\x00')[:CELL_SIZE]

# Parses a Tor cell
def parse_cell(cell: bytes):
    circ_id = int.from_bytes(cell[0:2], 'big')
    command = cell[2]
    recognized = cell[3:5]
    digest = cell[5:9]
    length = int.from_bytes(cell[9:11], 'big')
    payload = cell[11:11 + length]
    return (circ_id, command, recognized, digest, length, payload)
