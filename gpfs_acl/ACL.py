import re
from pathlib import Path
import subprocess

from gpfs_acl.ACLentry import ACLentry


class ACL:
    get_acl_cmd = "/usr/lpp/mmfs/bin/mmgetacl"
    put_acl_cmd = "/usr/lpp/mmfs/bin/mmputacl"

    def __init__(self, filename=None,
                 get_acl_cmd=None,
                 put_acl_cmd=None
                 ):

        if get_acl_cmd is not None:
            self.get_acl_cmd = get_acl_cmd
        if get_acl_cmd is not None:
            self.put_acl_cmd = put_acl_cmd

        self.owner = None
        self.group = None
        self.controls = {}
        self.reset()

        if filename is not None:
            self.file = Path(filename).expanduser().resolve()
            self.parse(self.read_string_from_file(self.file, get_acl_cmd=self.get_acl_cmd))
        else:
            self.file = None

    def reset(self):
        self.owner = None
        self.group = None
        self.controls = []

    def parse(self, acl_string):
        acl_string = acl_string.strip()
        self.reset()
        self.owner = self.parse_owner(acl_string)
        self.group = self.parse_group(acl_string)
        self.controls = self.parse_controls(acl_string)

    def cleanup(self):
        for entry in self.controls.values():
            if self.file is not None:
                if self.file.is_dir():
                    entry.is_dir()
                elif self.file.is_file():
                    entry.is_file()

            entry.derive_mode_from_special()

    def write_to_file(self):
        assert self.file is not None and self.file.exists(), f"File {self.file} does not exist"
        command = [self.put_acl_cmd, self.file.as_posix()]
        # result = subprocess.run(command, input=self.to_string().encode(), text=True, capture_output=True)
        # print(result.stderr)
        # print(result.stdout)
        print(self.to_string())

    def to_string(self):
        acl_string = "#NFSv4 ACL\n"
        acl_string += f"#owner:{self.owner}\n"
        acl_string += f"#group:{self.group}\n"
        for entry in self.controls.values():
            acl_string += entry.to_string() + "\n\n"

        return acl_string

    @staticmethod
    def parse_owner(acl_string):
        matches = re.findall(r'owner:(.*)', acl_string)
        return matches[0]

    @staticmethod
    def parse_group(acl_string):
        matches = re.findall(r'group:(.*)', acl_string)
        return matches[0]

    @staticmethod
    def parse_controls(acl_string):
        acl_lines = acl_string.split("\n")
        controls_start = 0
        while controls_start<len(acl_lines) and acl_lines[controls_start][0] == "#":
            controls_start += 1

        acl_string = "\n".join(acl_lines[controls_start:])
        control_strings = acl_string.split("\n\n")
        controls = {}
        for c in control_strings:
            aclentry = ACL.parse_control(c)
            aclename = f"{aclentry.qualifier}:{aclentry.subject}:{aclentry.acltype}"
            if aclename in controls:
                controls[aclename] += aclentry
            else:
                controls[aclename] = aclentry
        return controls

    @staticmethod
    def parse_control(control_string):
        return ACLentry.parse(control_string)

    @staticmethod
    def read_string_from_file(filename, get_acl_cmd=None):
        if get_acl_cmd is None:
            get_acl_cmd = ACL.get_acl_cmd
        assert filename is not None and filename.exists(), f"File {filename} does not exist"
        command = [get_acl_cmd, filename.as_posix()]
        result = subprocess.run(command, text=True, capture_output=True)
        print("Reading")
        print(result.stderr)
        print(result.stdout)
        return result.stdout
