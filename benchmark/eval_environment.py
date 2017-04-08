import ConfigParser
import argparse
import logging
import time
import datetime
import sys
import os
import subprocess
import threading


def readConfigFile(config_file):
    try:
        config_parser = ConfigParser.RawConfigParser()
        return config_parser if config_parser.read(config_file) else None

    except ConfigParser.MissingSectionHeaderError as e:
        logging.error(str(e))
    except ConfigParser.ParsingError as e:
        logging.error(str(e))
    except ConfigParser.Error as e:
        logging.critical(str(e))


def getConfigSections(config_parser, section):
    config_dic = {}
    options = config_parser.options(section)
    for option in options:
        try:
            config_dic[option] = config_parser.get(section, option)
            if config_dic[option] == -1:
                logging.error("skip: %s" % option)
        except:
            logging.error("exception on %s!" % option)
            config_dic[option] = None
    return config_dic


def getConfigFullPath(config_file):
    try:
        with open(config_file) as f:
            pass
    except IOError as e:
        logging.warning("'%s' does not exist" % config_file)
        return None
    return os.path.abspath(config_file)


def getTimeStamp():
    try:
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M%S')
    except:
        logging.warning("could not get time stamp")
        return None
    return st.replace("\n", "")


def kill_process(identifier, server_ip, server_user):
    while True:
        pid = os.popen(
            "ssh " + server_ip + " ps -ef | grep " + identifier + " | grep -v grep | awk '{print $2}' | head -n 1").read()

        if pid == "" or pid <= 1:
            break

        command = "sudo kill -9 " + pid
        ssh_remote_execute(command, server_user, server_ip, 2)


def is_app_running(command):
    assert len(command) > 0
    return True if os.system(command) == 0 else False


def ssh_remote_execute(recv_command, server_user, server_ip, seconds=1):
    os.system("ssh " + server_user + "@" + server_ip + " '" + recv_command + "'")
    time.sleep(seconds)


def ssh_remote_subprocess_master(recv_command, server_user, server_ip, server_cpu, server_memory, type):
    filename = "/home/hkucs/qemu_output/[" + type + "]log-" + server_ip + "-cpu[" + server_cpu + "]-mem[" + server_memory + "]-" + getTimeStamp()
    # fobj = open(filename, "w")
    # ssh_remote_execute("ln -fs " + filename + " /home/hkucs/qemu_output/latest_master_log", server_user, server_ip)
    os.system("ln -fs " + filename + " /home/hkucs/qemu_output/latest_master_log")
    log = subprocess.Popen("nohup ssh " + server_user + "@" + server_ip + " " + recv_command
                           + " > " + filename + " &", shell=True, stdout=subprocess.PIPE)


def ssh_remote_subprocess_slave(recv_command, server_user, server_ip, primary_ip, server_cpu, server_memory, type):
    filename = "/home/hkucs/qemu_output/[" + type + "]log-" + server_ip + "-cpu[" + server_cpu + "]-mem[" + server_memory + "]-" + getTimeStamp()
    # fobj = open(filename, "w")
    # ssh_remote_execute("ln -fs " + filename + " /home/hkucs/qemu_output/latest_slave_log", server_user, primary_ip)
    os.system("ln -fs " + filename + " /home/hkucs/qemu_output/latest_slave_log")
    log = subprocess.Popen("nohup ssh " + server_user + "@" + server_ip + " " + recv_command
                           + " > " + filename + " &", shell=True, stdout=subprocess.PIPE)


def ssh_remote_nc(recv_command, server_user, server_ip, telnet_ip, telnet_port, seconds=1):
    os.system("ssh " + server_user + "@" + server_ip +
              ' echo "' + recv_command +
              '" | nc ' + telnet_ip + " " + telnet_port)
    time.sleep(seconds)


def init_dirty_pages(recv_command, server_user, server_ip):
    ssh_remote_execute(recv_command, server_user, server_ip)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-s %(levelname)-s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename='/tmp/rdma4qemu.log',
                        filemode='w')
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-s: %(levelname)-s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)
    logger = logging.getLogger()

    # 1. read environment conf

    # Parse args and give some help how to handle this file
    parser = argparse.ArgumentParser(description='Environment Initialization')
    parser.add_argument('--mode', '-m', choices=('start', 'stop'),
                        type=str,
                        help="start or shutdown the environment")
    parser.add_argument('--filename', '-f',
                        type=str,
                        help="include a environment setting script")
    parser.add_argument('--type', '-t', choices=('mc', 'colo', 'norep', "vmft"),
                        type=str,
                        help="choose an environment to start or stop")
    parser.add_argument('--cpu', '-cpu',
                        type=str,
                        help="input the number of cpu cores")
    parser.add_argument('--memory', '-mem',
                        type=str,
                        help="input the memory size")
    parser.add_argument('--primary', '-primary',
                        type=str)
    parser.add_argument('--secondary', '-secondary',
                        type=str)

    args = parser.parse_args()

    mode = args.mode
    config_file = args.filename
    type = args.type
    CPU = args.cpu
    MEMORY = args.memory
    PRIMARY_IP = args.primary
    SECONDARY_IP = args.secondary

    logging.info("processing '" + config_file + "'")
    full_path = getConfigFullPath(config_file)

    local_config = readConfigFile(full_path)

    # 2. determine the running environment
    OPTION = getConfigSections(local_config, "KVM_CONFIG")['option']
    # PRIMARY_IP = getConfigSections(local_config, "KVM_CONFIG")['primary_ip']
    PRIMARY_PORT = getConfigSections(local_config, "KVM_CONFIG")['primary_port']
    # SECONDARY_IP = getConfigSections(local_config, "KVM_CONFIG")['secondary_ip']
    SECONDARY_PORT = getConfigSections(local_config, "KVM_CONFIG")['secondary_port']
    PRIMARY_QEMU_PATH = getConfigSections(local_config, "KVM_CONFIG")['primary_qemu_path']
    SECONDARY_QEMU_PATH = getConfigSections(local_config, "KVM_CONFIG")['secondary_qemu_path']
    PRIMARY_USERNAME = getConfigSections(local_config, "KVM_CONFIG")['primary_username']
    SECONDARY_USERNAME = getConfigSections(local_config, "KVM_CONFIG")['secondary_username']

    if type in ['mc', 'norep']:
        QEMU_MONITOR_ENABLE_MC = getConfigSections(local_config, "KVM_MC")['qemu_monitor_enable_mc']
        # CPU = getConfigSections(local_config, "KVM_MC")['cpu']
        # MEMORY = getConfigSections(local_config, "KVM_MC")['memory']
        TELNET_IP = getConfigSections(local_config, "KVM_MC")['telnet_ip']
        TELNET_PORT = getConfigSections(local_config, "KVM_MC")['telnet_port']
        MASTER_MIRROR = getConfigSections(local_config, "KVM_MC")['master_mirror']
        SLAVE_MIRROR = getConfigSections(local_config, "KVM_MC")['slave_mirror']
        TCP_ADDRESS = getConfigSections(local_config, "KVM_MC")['tcp_address']
        REMOTE_DIRTY_INIT_COMMAND = getConfigSections(local_config, "KVM_MC")['remote_dirty_init_command']
        VM_USER = getConfigSections(local_config, "KVM_MC")['vm_user']
        VM_IP = getConfigSections(local_config, "KVM_MC")['vm_ip']
        NUMIFBS = getConfigSections(local_config, "KVM_MC")['numifbs']
        QEMU_MONITOR_ENABLE_MC_DISK_DISABLE = getConfigSections(local_config, "KVM_MC")[
            'qemu_monitor_enable_mc_disk_disable']
        QEMU_MONITOR_ENABLE_MC_NET_DISABLE = getConfigSections(local_config, "KVM_MC")[
            'qemu_monitor_enable_mc_net_disable']
        MIGRATE_SET_MC_DELAY = getConfigSections(local_config, "KVM_MC")['migrate_set_mc_delay']
        QEMU_MONITOR_START_MC = getConfigSections(local_config, "KVM_MC")['qemu_monitor_start_mc']
    elif type == "colo":
        # MEMORY = getConfigSections(local_config, "KVM_COLO_MASTER")['memory']
        # CPU = getConfigSections(local_config, "KVM_COLO_MASTER")['cpu']
        CHILDREN_FILE_NAME = getConfigSections(local_config, "KVM_COLO_MASTER")['children_file_name']
        MASTER_NF_CONNTRACK_COLO = getConfigSections(local_config, "KVM_COLO_MASTER")['master_nf_conntrack_colo']
        MASTER_XT_PMYCOLO = getConfigSections(local_config, "KVM_COLO_MASTER")['master_xt_pmycolo']
        MASTER_NFNETLINK_COLO = getConfigSections(local_config, "KVM_COLO_MASTER")['master_nfnetlink_colo']
        MASTER_XT_MARK = getConfigSections(local_config, "KVM_COLO_MASTER")['master_xt_mark']
        MASTER_KVM_INTEL = getConfigSections(local_config, "KVM_COLO_MASTER")['master_kvm_intel']
        MASTER_NF_CONNTRACK_IPV4 = getConfigSections(local_config, "KVM_COLO_MASTER")['master_nf_conntrack_ipv4']
        MASTER_VHOST_NET = getConfigSections(local_config, "KVM_COLO_MASTER")['master_vhost_net']
        MASTER_EXPERIMENTAL_ZCOPYTX = getConfigSections(local_config, "KVM_COLO_MASTER")['master_experimental_zcopytx']
        MASTER_TELNET_IP = getConfigSections(local_config, "KVM_COLO_MASTER")['master_telnet_ip']
        MASTER_TELNET_PORT = getConfigSections(local_config, "KVM_COLO_MASTER")['master_telnet_port']
        MASTER_CHILD_ADD = getConfigSections(local_config, "KVM_COLO_MASTER")['master_child_add']
        MASTER_MIGRATE_SET_CAPABILITY = getConfigSections(local_config, "KVM_COLO_MASTER")['master_migrate_set_capability']
        MASTER_MIGRATE_TCP = getConfigSections(local_config, "KVM_COLO_MASTER")['master_migrate_tcp']

        ACTIVE_IMG = getConfigSections(local_config, "KVM_COLO_SLAVE")['active_img']
        HIDDEN_IMG = getConfigSections(local_config, "KVM_COLO_SLAVE")['hidden_img']
        SLAVE_XT_SECCOLO = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_xt_seccolo']
        SLAVE_NF_CONNTRACK_COLO = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_nf_conntrack_colo']
        SLAVE_NFNETLINK_COLO = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_nfnetlink_colo']
        SLAVE_NF_CONNTRACK_IPV4 = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_nf_conntrack_ipv4']
        SLAVE_KVM_INTEL = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_kvm_intel']
        SLAVE_VHOST_NET = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_vhost_net']
        SLAVE_EXPERIMENTAL_ZCOPYTX = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_experimental_zcopytx']
        SLAVE_TELNET_IP = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_telnet_ip']
        SLAVE_TELNET_PORT = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_telnet_port']
        SLAVE_NBD_SERVER_START = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_nbd_server_start']
        SLAVE_NBD_SERVER_ADD = getConfigSections(local_config, "KVM_COLO_SLAVE")['slave_nbd_server_add']

    elif type == "vmft":
        CHILDREN_FILE_NAME = getConfigSections(local_config, "VM_FT_MASTER")['children_file_name']
        ACTIVE_IMG = getConfigSections(local_config, "VM_FT_MASTER")['active_img']
        HIDDEN_IMG = getConfigSections(local_config, "VM_FT_MASTER")['hidden_img']
        NUMIFBS = getConfigSections(local_config, "VM_FT_MASTER")['numifbs']
        FILE_HOST = getConfigSections(local_config, "VM_FT_MASTER")['file_host']
        FILE_PORT = getConfigSections(local_config, "VM_FT_MASTER")['file_port']
        X_CHECKPOINT_DELAY = getConfigSections(local_config, "VM_FT_MASTER")['x_checkpoint_delay']
        TCP_ADDRESS = getConfigSections(local_config, "VM_FT_MASTER")['tcp_address']
        MASTER_TELNET_IP = getConfigSections(local_config, "VM_FT_MASTER")['master_telnet_ip']
        MASTER_TELNET_PORT = getConfigSections(local_config, "VM_FT_MASTER")['master_telnet_port']

        NDBSERVER_HOST = getConfigSections(local_config, "VM_FT_SLAVE")['ndbserver_host']
        NDBSERVER_PORT = getConfigSections(local_config, "VM_FT_SLAVE")['ndbserver_port']
        SLAVE_TELNET_IP = getConfigSections(local_config, "VM_FT_SLAVE")['slave_telnet_ip']
        SLAVE_TELNET_PORT = getConfigSections(local_config, "VM_FT_SLAVE")['slave_telnet_port']

    # 3. launch or shutdown the environment
    if mode == "start":
        if type in ['norep', 'mc']:
            command = "sudo " + PRIMARY_QEMU_PATH +"qemu/x86_64-softmmu/qemu-system-x86_64 " + \
                      MASTER_MIRROR + " -m " + MEMORY + " -smp " + CPU + \
                      " -cpu host --enable-kvm -netdev tap,id=net0,ifname=tap0," \
                      "script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown " \
                      "-device e1000,netdev=net0,mac=18:66:da:03:15:b1 " \
                      "-monitor telnet:" + TELNET_IP + ":" + TELNET_PORT + \
                      ",server,nowait -vnc :8"
            # ssh_remote_execute(command, PRIMARY_USERNAME, PRIMARY_IP, 5)
            t1 = threading.Thread(target=ssh_remote_subprocess_master,
                                  args=(command, PRIMARY_USERNAME, PRIMARY_IP, CPU, MEMORY, type))
            t1.start()
            time.sleep(5)

            if type == "mc":
                command = "sudo " + SECONDARY_QEMU_PATH + "qemu/x86_64-softmmu/qemu-system-x86_64" + \
                          SLAVE_MIRROR + " -m " + MEMORY + " -smp " + CPU + \
                          " -cpu host --enable-kvm -netdev tap,id=net0," \
                          "ifname=tap0,script=/etc/qemu-ifup," \
                          "downscript=/etc/qemu-ifdown -device e1000," \
                          "netdev=net0,mac=18:66:da:03:15:b1 -vnc :8 " \
                          "-incoming tcp:" + TCP_ADDRESS
                # ssh_remote_execute(command, SECONDARY_USERNAME, SECONDARY_IP, 5)
                t2 = threading.Thread(target=ssh_remote_subprocess_slave,
                                      args=(command, SECONDARY_USERNAME, SECONDARY_IP, PRIMARY_IP, CPU, MEMORY, type))
                t2.start()
                time.sleep(5)

                init_dirty_pages(REMOTE_DIRTY_INIT_COMMAND, VM_USER, VM_IP)
                ssh_remote_execute("sudo modprobe ifb numifbs=" + NUMIFBS, PRIMARY_USERNAME, PRIMARY_IP, 2)
                ssh_remote_execute("sudo ip link set up ifb0", PRIMARY_USERNAME, PRIMARY_IP, 2)
                ssh_remote_execute("sudo tc qdisc add dev tap0 ingress", PRIMARY_USERNAME, PRIMARY_IP, 2)
                ssh_remote_execute("sudo tc filter add dev tap0 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb0",
                                   PRIMARY_USERNAME, PRIMARY_IP, 2)

                ssh_remote_nc(QEMU_MONITOR_ENABLE_MC, PRIMARY_USERNAME, PRIMARY_IP, TELNET_IP, TELNET_PORT, 2)
                ssh_remote_nc(QEMU_MONITOR_ENABLE_MC_DISK_DISABLE, PRIMARY_USERNAME, PRIMARY_IP, TELNET_IP, TELNET_PORT, 2)
                ssh_remote_nc(MIGRATE_SET_MC_DELAY, PRIMARY_USERNAME, PRIMARY_IP, TELNET_IP, TELNET_PORT, 2)
                # ssh_remote_nc(QEMU_MONITOR_ENABLE_MC_NET_DISABLE, PRIMARY_USERNAME, PRIMARY_IP, TELNET_IP, TELNET_PORT, 2)
                ssh_remote_nc(QEMU_MONITOR_START_MC, PRIMARY_USERNAME, PRIMARY_IP, TELNET_IP, TELNET_PORT, 2)

        elif type == "colo":
            # try:
                ####Master Server####
                # ssh_remote_execute(MASTER_NF_CONNTRACK_COLO, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_XT_PMYCOLO, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_NFNETLINK_COLO, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_XT_MARK, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_KVM_INTEL, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_NF_CONNTRACK_IPV4, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_VHOST_NET, PRIMARY_USERNAME, PRIMARY_IP, 1)
                # ssh_remote_execute(MASTER_EXPERIMENTAL_ZCOPYTX, PRIMARY_USERNAME, PRIMARY_IP, 1)
                command = "sudo " + PRIMARY_QEMU_PATH + \
                          "x86_64-softmmu/qemu-system-x86_64 -cpu host -machine pc-i440fx-2.3," \
                          "accel=kvm,usb=off -netdev tap,id=hn0," \
                          "script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown," \
                          "colo_script=/home/hkucs/qemu/scripts/colo-proxy-script.sh," \
                          "forward_nic=eth1 -device virtio-net-pci," \
                          "id=net-pci0,netdev=hn0 -boot c -drive if=virtio," \
                          "id=disk1,driver=quorum,read-pattern=fifo," \
                          "cache=none,aio=native,children.0.file.filename=" + CHILDREN_FILE_NAME + \
                          ",children.0.driver=raw " \
                          " -m " + MEMORY + " -smp " + CPU + \
                          " -device piix3-usb-uhci -device usb-tablet " \
                          "-monitor telnet:" + MASTER_TELNET_IP + ":" + MASTER_TELNET_PORT + ",server,nowait"
                t1 = threading.Thread(target=ssh_remote_subprocess_master,
                                      args=(command, PRIMARY_USERNAME, PRIMARY_IP, CPU, MEMORY, type))
                t1.start()
                time.sleep(5)
                # ssh_remote_subprocess(command, PRIMARY_USERNAME, PRIMARY_IP, 10)

                ####Slave Server####
                # ssh_remote_execute(SLAVE_XT_SECCOLO, SECONDARY_USERNAME, SECONDARY_IP, 1)
                # ssh_remote_execute(SLAVE_NF_CONNTRACK_COLO, SECONDARY_USERNAME, SECONDARY_IP, 1)
                # ssh_remote_execute(SLAVE_NFNETLINK_COLO, SECONDARY_USERNAME, SECONDARY_IP, 1)
                # ssh_remote_execute(SLAVE_NF_CONNTRACK_IPV4, SECONDARY_USERNAME, SECONDARY_IP, 1)
                # ssh_remote_execute(SLAVE_KVM_INTEL, SECONDARY_USERNAME, SECONDARY_IP, 1)
                # ssh_remote_execute(SLAVE_VHOST_NET, SECONDARY_USERNAME, SECONDARY_IP, 1)
                # ssh_remote_execute(SLAVE_EXPERIMENTAL_ZCOPYTX, SECONDARY_USERNAME, SECONDARY_IP, 1)
                command = "sudo " + SECONDARY_QEMU_PATH + "x86_64-softmmu/qemu-system-x86_64 -machine " \
                                                          "pc-i440fx-2.3,accel=kvm,usb=off -cpu host -netdev tap,id=hn0," \
                                                          "script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown," \
                                                          "colo_script=/home/hkucs/qemu/scripts/colo-proxy-script.sh," \
                                                          "forward_nic=eth6 -device virtio-net-pci," \
                                                          "id=net-pci0,netdev=hn0" +  \
                                                          " -drive if=none,driver=raw," + "file=" + CHILDREN_FILE_NAME + \
                                                          ",id=colo1,cache=none,aio=native -drive if=virtio," \
                                                          "driver=replication,mode=secondary," \
                                                          "throttling.bps-total-max=70000000," + \
                                                          "file.file.filename=" + ACTIVE_IMG + \
                                                          ",file.driver=qcow2," + \
                                                          "file.backing.file.filename=" + HIDDEN_IMG + \
                                                          ",file.backing.driver=qcow2," \
                                                          "file.backing.backing.backing_reference=colo1," \
                                                          "file.backing.allow-write-backing-file=on " + \
                                                          " -m " + MEMORY + " -smp " + CPU + \
                                                          " -device piix3-usb-uhci -device usb-tablet " \
                                                          "-monitor telnet:" + SLAVE_TELNET_IP + ":" + \
                                                            SLAVE_TELNET_PORT + ",server,nowait " \
                                                          "-incoming tcp:0:8888"
                t2 = threading.Thread(target=ssh_remote_subprocess_slave,
                                      args=(command, SECONDARY_USERNAME, SECONDARY_IP, PRIMARY_IP, CPU, MEMORY, type))
                t2.start()
                time.sleep(5)
                # ssh_remote_subprocess(command, SECONDARY_USERNAME, SECONDARY_IP, 10)

                # 1. Slave Colo Setting
                ssh_remote_nc(SLAVE_NBD_SERVER_START, SECONDARY_USERNAME, SECONDARY_IP, SLAVE_TELNET_IP, SLAVE_TELNET_PORT, 2)
                ssh_remote_nc(SLAVE_NBD_SERVER_ADD, SECONDARY_USERNAME, SECONDARY_IP, SLAVE_TELNET_IP, SLAVE_TELNET_PORT, 2)
                # 2. Master Colo Setting
                ssh_remote_nc(MASTER_CHILD_ADD, PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
                ssh_remote_nc(MASTER_MIGRATE_SET_CAPABILITY, PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
                ssh_remote_nc(MASTER_MIGRATE_TCP, PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)

        elif type == "vmft":
            command = "sudo LD_LIBRARY_PATH=$VMFT_ROOT/rdma-paxos/target:$LD_LIBRARY_PATH " \
                      "x86_64-softmmu/qemu-system-x86_64 -cpu host -enable-kvm -boot c " \
                      "-m " + MEMORY + " -smp " + CPU + " -qmp stdio -vnc :8 " \
                      "-name primary -cpu qemu64,+kvmclock -device piix3-usb-uhci " \
                      "-drive if=virtio,id=colo-disk0,driver=quorum,read-pattern=fifo," \
                      "vote-threshold=1,children.0.file.filename=" + CHILDREN_FILE_NAME + ",children.0.driver=raw -S " \
                      "-netdev tap,id=hn0,vhost=off," \
                      "script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown " \
                      "-device e1000,id=e0,netdev=hn0,mac=52:a4:00:12:78:66 " \
                      "-monitor telnet:" + MASTER_TELNET_IP + ":" + MASTER_TELNET_PORT + ",server,nowait"

            t1 = threading.Thread(target=ssh_remote_subprocess_master,
                                  args=(command, PRIMARY_USERNAME, PRIMARY_IP, CPU, MEMORY, type))
            t1.start()
            time.sleep(5)

            command = "sudo LD_LIBRARY_PATH=$VMFT_ROOT/rdma-paxos/target:$LD_LIBRARY_PATH " \
                      "x86_64-softmmu/qemu-system-x86_64 -cpu host -boot c " \
                      "-m " + MEMORY + " -smp " + CPU + " -qmp stdio -vnc :8 " \
                      "-name secondary -enable-kvm -cpu qemu64," \
                      "+kvmclock -device piix3-usb-uhci -drive if=none,id=colo-disk0," \
                      "file.filename=" + CHILDREN_FILE_NAME + \
                      ",driver=raw,node-name=node0 -drive if=virtio,id=active-disk0,driver=replication," \
                      "mode=secondary,file.driver=qcow2,top-id=active-disk0," \
                      "file.file.filename=" + ACTIVE_IMG + \
                      ",file.backing.driver=qcow2," \
                      "file.backing.file.filename=" + HIDDEN_IMG + \
                      ",file.backing.backing=colo-disk0 " \
                      "-netdev tap,id=hn0,vhost=off,script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown " \
                      "-device e1000,netdev=hn0,mac=52:a4:00:12:78:66 " \
                      "-chardev socket,id=red0,path=/dev/shm/mirror.sock " \
                      "-chardev socket,id=red1,path=/dev/shm/redirector.sock " \
                      "-object filter-redirector,id=f1,netdev=hn0,queue=tx,indev=red0 " \
                      "-object filter-redirector,id=f2,netdev=hn0,queue=rx,outdev=red1 " \
                      "-monitor telnet:" + SLAVE_TELNET_IP + ":" + SLAVE_TELNET_PORT + \
                      ",server,nowait " \
                      "-incoming tcp:" + TCP_ADDRESS
            t2 = threading.Thread(target=ssh_remote_subprocess_slave,
                                  args=(command, SECONDARY_USERNAME, SECONDARY_IP, PRIMARY_IP, CPU, MEMORY, type))
            t2.start()
            time.sleep(20)

            ssh_remote_execute("sudo modprobe ifb numifbs=" + NUMIFBS, PRIMARY_USERNAME, PRIMARY_IP, 2)
            ssh_remote_execute("sudo ip link set up ifb0", PRIMARY_USERNAME, PRIMARY_IP, 2)
            ssh_remote_execute("sudo tc qdisc add dev tap0 ingress", PRIMARY_USERNAME, PRIMARY_IP, 2)
            ssh_remote_execute("sudo tc filter add dev tap0 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb0",
                               PRIMARY_USERNAME, PRIMARY_IP, 2)

            # Backup JSON
            ssh_remote_nc("{'execute':'qmp_capabilities'}", SECONDARY_USERNAME, SECONDARY_IP, SLAVE_TELNET_IP, SLAVE_TELNET_PORT, 2)
            ssh_remote_nc("{ 'execute': 'nbd-server-start','arguments': {'addr': {'type': 'inet', 'data': {'host': '" + NDBSERVER_HOST +
                          "', 'port': '" + NDBSERVER_PORT + "'}}}}", SECONDARY_USERNAME, SECONDARY_IP, SLAVE_TELNET_IP, SLAVE_TELNET_PORT, 2)
            ssh_remote_nc("{'execute': 'nbd-server-add', 'arguments': {'device': 'colo-disk0', 'writable': true } }",
                          SECONDARY_USERNAME, SECONDARY_IP, SLAVE_TELNET_IP, SLAVE_TELNET_PORT, 2)

            # Primary JSON
            ssh_remote_nc("{'execute':'qmp_capabilities'}", PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
            ssh_remote_nc("{'execute': 'human-monitor-command','arguments': {'command-line': 'drive_add -n buddy "
                          "driver=replication,mode=primary,file.driver=nbd,file.host=10.22.1.3,file.port=8889,"
                          "file.export=colo-disk0,node-name=node0'}}",
                          PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
            ssh_remote_nc("{'execute':'x-blockdev-change', 'arguments':{'parent': 'colo-disk0', 'node': 'node0'}}",
                          PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
            ssh_remote_nc("{'execute': 'migrate-set-capabilities','arguments': {'capabilities': [{'capability': 'x-colo', 'state': true }]}}",
                          PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
            ssh_remote_nc("{'execute': 'migrate-set-parameters' , 'arguments': { 'x-checkpoint-delay': " + X_CHECKPOINT_DELAY + "}}",
                          PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)
            ssh_remote_nc("{'execute': 'migrate', 'arguments': {'uri': 'tcp:" + TCP_ADDRESS + "'}}",
                          PRIMARY_USERNAME, PRIMARY_IP, MASTER_TELNET_IP, MASTER_TELNET_PORT, 2)

    elif mode == "stop":
        try:
            kill_process("qemu-system-x86_64", server_ip=PRIMARY_IP, server_user=PRIMARY_USERNAME)
            kill_process("qemu-system-x86_64", server_ip=SECONDARY_IP, server_user=SECONDARY_USERNAME)
        except:
            logging.error("vm stop error")
