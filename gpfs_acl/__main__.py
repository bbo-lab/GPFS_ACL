from gpfs_acl.ACL import ACL


def main():
    acl = ACL("/gpfs/soma_fs/bbo/analysis")
    acl.cleanup()
    print(acl.to_string())


if __name__ == '__main__':
    main()
