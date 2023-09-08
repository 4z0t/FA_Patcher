import re

MACRO_NAME = "ADDR"


CHUNK_SIZE = 4096


def each_chunk(stream, separator):
    buffer = ""
    while True:  # until EOF
        chunk = stream.read(CHUNK_SIZE)  # I propose 4096 or so
        if not chunk:  # EOF?
            yield buffer
            break
        buffer += chunk
        while True:  # until no separator is found
            try:
                part, buffer = buffer.split(separator, 1)
            except ValueError:
                break
            else:
                yield part


def get_addresses(filename):
    functions = {}
    with open(filename, "r") as file:
        for line in each_chunk(file, separator=";"):
            line = line.replace("\n", " ")
            m = re.match(
                ".*ADDR\((0x[0-9A-Fa-f]{6,8})\).* ([_a-zA-Z][_a-zA-Z0-9]*)\(.*\)",
                line,
            )
            if m:
                functions[int(m.group(1), 16)] = m.group(2)
    return functions


if __name__ == "__main__":
    addresses = get_addresses("test.cpp")
    print(addresses)
