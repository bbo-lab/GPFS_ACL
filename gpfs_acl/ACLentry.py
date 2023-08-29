import re
from copy import deepcopy


class ACLentry:
    perms_all = ["READ/LIST", "WRITE/CREATE", "APPEND/MKDIR", "SYNCHRONIZE", "READ_ACL", "READ_ATTR", "READ_NAMED",
                 "DELETE", "DELETE_CHILD", "CHOWN", "EXEC/SEARCH", "WRITE_ACL", "WRITE_ATTR", "WRITE_NAMED"]
    perm_str_len = [9, 12, 12, 11, 9, 10, 11, 9, 12, 12, 11, 9, 10, 11]
    perm_modes = ["r", "wc", "wc", None, "r", "r", "r", "wc", "wc", None, "x", "wc", "wc", "wc"]
    flags_all = ["FileInherit", "DirInherit", "NoPropagateInherit", "InheritOnly", "InheritNoPropagate"]
    mode_all = "rwxc"

    def __init__(self, qualifier, subject, mode, acltype, flags, permissions):
        self.qualifier = qualifier
        self.subject = subject
        self.mode = mode
        self.acltype = acltype
        self.flags = flags
        self.permissions = permissions

        assert self.acltype == "allow", "deny and audit ACL not supported"

    def combine(self, comb_entry):
        res = deepcopy(self)

        for m in res.mode_all:
            if m in comb_entry.mode:
                if m not in res.mode:
                    res.mode[m] = comb_entry.mode[m]
                else:
                    res.mode[m] = res.mode[m] | comb_entry.mode[m]

        for m in res.flags_all:
            if m in comb_entry.flags:
                if m not in res.flags:
                    res.flags[m] = comb_entry.flags[m]
                else:
                    res.flags[m] = res.flags[m] | comb_entry.flags[m]

        for m in res.perms_all:
            if m in comb_entry.permissions:
                if m not in res.permissions:
                    res.permissions[m] = comb_entry.permissions[m]
                else:
                    res.permissions[m] = res.permissions[m] | comb_entry.permissions[m]

        return res

    def __add__(self, o):
        return self.combine(o)

    def is_file(self):
        self.flags = {}

    def is_dir(self):
        pass

    def derive_mode_from_special(self):
        for p in self.mode:
            self.mode[p] = False

        for p, m in zip(ACLentry.perms_all, ACLentry.perm_modes):
            if m is None:
                continue

            if p in self.permissions and self.permissions[p]:
                for m_a in ACLentry.mode_all:
                    if m_a in m:
                        self.mode[m_a] = True

    def to_string(self):
        return self.subjectline_to_string() + "\n" + self.permissions_to_string()

    def subjectline_to_string(self):
        aclstring = f"{self.qualifier}:{self.subject}:{self.mode_to_string()}:{self.acltype}"

        flagsstring = self.flags_to_string()
        if len(flagsstring) > 0:
            aclstring += ":" + flagsstring

        return aclstring

    def mode_to_string(self):
        modestring = ""
        for m in ACLentry.mode_all:
            if m in self.mode and self.mode[m]:
                modestring += m
            else:
                modestring += "-"

        return modestring

    def flags_to_string(self):
        flaglist = []
        for m in ACLentry.flags_all:
            if m in self.flags and self.flags[m]:
                flaglist.append(m)

        return ":".join(flaglist)

    def permissions_to_string(self):
        permstring = ""
        for i_p, perm in enumerate(ACLentry.perms_all):
            if perm in self.permissions and self.permissions[perm]:
                permstring += " (X)"
            else:
                permstring += " (-)"
            permstring += f"{perm: <{ACLentry.perm_str_len[i_p]}}"

            if perm == "READ_NAMED":
                permstring += "\n"

        return permstring

    @staticmethod
    def parse(control_string):
        control_string = control_string.strip()
        control_string = control_string.split("\n")

        qualifier, subject, mode, acltype, flags = ACLentry.parse_subjectline(control_string[0])
        permissions = ACLentry.parse_permissions("\n".join(control_string[1:]))

        return ACLentry(qualifier, subject, mode, acltype, flags, permissions)

    @staticmethod
    def parse_permissions(control_string):
        res = re.findall(r"\([X-]\)", control_string)
        assert len(res) == len(ACLentry.perms_all), "Result does not match permissions"
        permission_dict = {}
        for perm, check in zip(ACLentry.perms_all, res):
            if check == "(X)":
                permission_dict[perm] = True
            else:
                permission_dict[perm] = False

        return permission_dict

    @staticmethod
    def parse_subjectline(control_string):
        parts = control_string.split(":")
        qualifier = parts[0]
        subject = parts[1]

        mode = {}
        for m in ACLentry.mode_all:
            if m in parts[2]:
                mode[m] = True
            else:
                mode[m] = False

        acltype = parts[3]

        flags = {}
        for f in ACLentry.flags_all:
            if f in parts[4:]:
                flags[f] = True
            else:
                flags[f] = False

        return qualifier, subject, mode, acltype, flags
