from gpfs_acl.ACL import ACL


def main():
    acl = ACL("/home/voit/MATLAB/bbo/projects/junker-bird/python/blender/bboviso/trajectory.py")
    acl.cleanup()
    print(acl.to_string())


if __name__ == '__main__':
    main()
