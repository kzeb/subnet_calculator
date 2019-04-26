import socket
import struct
import subprocess


f = open("file.txt", "w+")


def user_ip():
    value_local = []
    value_local_1 = socket.gethostbyname(socket.gethostname())
    cmd = ['ipconfig', 'getoption', 'en0', 'subnet_mask']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o, e = proc.communicate()
    value_local_2 = sum(bin(int(x)).count('1') for x in o.decode('ascii').split('.'))
    value_local.append(str(value_local_1))
    value_local.append(str(value_local_2))
    return value_local


def user_input_and_check():
    while True:
        value_entered = input("\nEnter an IP address and a subnet mask using following format:\na.b.c.d/mask\n")\
            .split('/')
        if value_entered == ['']:
            return user_ip()
        ip_address = value_entered[0].split('.')
        subnet_mask = value_entered[1]

        if (len(ip_address) == 4) and (1 <= int(ip_address[0]) <= 255) and (0 <= int(ip_address[1]) <= 255) and \
                (0 <= int(ip_address[2]) <= 255) and (0 <= int(ip_address[3]) <= 255):
            if (int(subnet_mask) <= 32) and (int(subnet_mask) >= 1):
                return value_entered
            else:
                print("\nThe subnet mask you have entered is incorrect! Please try again.\n")
                continue
        else:
            if (int(subnet_mask) <= 32) and (int(subnet_mask) >= 1):
                print("\nThe IP address you have entered is incorrect! Please try again.\n")
            else:
                print("\nThe IP and the subnet mask you have entered are both incorrect! Please try again.\n")
                continue
            continue


def cidr_to_netmask(cidr):
    network = cidr[0].split('.')
    net_bits = cidr[1]
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits))).split('.')
    return network, netmask


def network_bin(ip_address, subnet_mask):
    ip = ip_address
    mask = subnet_mask
    print("\n\nIP binary: ", end='')
    f.write("\n\nIP binary: ")
    for i in range(4):
        ip[i] = "{0:b}".format(int(ip[i]))
        ip[i] = (8 - len(str(ip[i]))) * '0' + str(ip[i])
        print(ip[i], end='')
        f.write(ip[i])
        if i < 3:
            print(".", end='')
            f.write(".")

    print('')

    print("Mask binary: ", end='')
    f.write("\nMask binary: ")
    for i in range(4):
        mask[i] = "{0:b}".format(int(mask[i]))
        mask[i] = (8 - len(str(mask[i]))) * '0' + str(mask[i])
        print(mask[i], end='')
        f.write(mask[i])
        if i < 3:
            print(".", end='')
            f.write(".")
    return ip, mask


def network_address(ip_address, sub_mask):
    network_address_binary = []
    for i in range(4):
        net_address = int(ip_address[i], 2) & int(sub_mask[i], 2)
        net_address = bin(net_address)
        net_address = str(net_address).replace("0b", "")
        network_address_binary.append("0" * (8 - len(net_address)) + net_address)
        print("0" * (8 - len(net_address)) + net_address, end='')
        f.write("0" * (8 - len(net_address)) + net_address)
        if i < 3:
            print(".", end='')
            f.write(".")
    return network_address_binary


def broadcast_address(sub_mask, n_address):
    broadcast_address_binary = []
    for i in range(4):
        temp = ""
        for j in range(8):
            if sub_mask[i][j] == '1':
                temp += '0'
            elif sub_mask[i][j] == '0':
                temp += '1'
        bro_address = bin(int(temp, 2))
        bro_address = str(bro_address).replace("0b", "")
        bro_address = addition_bin(bro_address, n_address[i])
        broadcast_address_binary.append("0" * (8 - len(bro_address)) + bro_address)
        print("0" * (8 - len(bro_address)) + bro_address, end='')
        f.write("0" * (8 - len(bro_address)) + bro_address)
        if i < 3:
            print(".", end='')
            f.write(".")
    return broadcast_address_binary


def addition_bin(x, y):
    max_len = max(len(x), len(y))
    x = x.zfill(max_len)
    y = y.zfill(max_len)
    result = ''
    carry = 0
    for i in range(max_len - 1, -1, -1):
        r = carry
        r += 1 if x[i] == '1' else 0
        r += 1 if y[i] == '1' else 0
        result = ('1' if r % 2 == 1 else '0') + result
        carry = 0 if r < 2 else 1
    if carry != 0:
        result = '1' + result
    return result.zfill(max_len)


def ip_class(ip):
    if int(ip[0], 2) <= 127:
        return "A"
    elif 127 < int(ip[0], 2) < 192 and int(ip[1], 2) < 255:
        return "B"
    elif int(ip[0], 2) > 191 and int(ip[1], 2) < 224 and int(ip[2], 2) < 255:
        return "C"
    elif 223 < int(ip[0], 2) < 240 and int(ip[3], 2) < 255:
        return "D"
    else:
        return "E"


def max_hosts(mask):
    return 2**(32-int(mask))-2


def is_private(ip):
    ip_address = ip.split('.')
    if int(ip_address[0]) == 10 and 0 <= int(ip_address[1]) <= 255 and 0 <= int(ip_address[2]) <= 255 \
            and 0 <= int(ip_address[3]) <= 255:
        return "Private"
    elif int(ip_address[0]) == 172 and 16 <= int(ip_address[1]) <= 31 and 0 <= int(ip_address[2]) <= 255 \
            and 0 <= int(ip_address[3]) <= 255:
        return "Private"
    elif int(ip_address[0]) == 192 and int(ip_address[1]) == 168 and 0 <= int(ip_address[2]) <= 255 \
            and 0 <= int(ip_address[3]) <= 255:
        return "Private"
    else:
        return "Public"


def is_host(ip_o, minv, maxv):
    ip = ip_o.split('.')
    if int(minv[0], 2) <= int(ip[0]) <= int(maxv[0], 2) and int(minv[1], 2) <= int(ip[1]) <= int(maxv[1], 2) \
            and int(minv[2], 2) <= int(ip[2]) <= int(maxv[2], 2) \
            and int(minv[3], 2)+1 <= int(ip[3]) <= int(maxv[3], 2)-1:
        while True:
            in_val = input("\n\nWould you like to ping the IP address you have entered? (Y/N)  ")
            if in_val == 'Y' or in_val == 'y':
                print(ip_o)
                cmd = ['ping', ip_o, '-c', '4']
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                o, e = proc.communicate()
                print(o.decode('ascii'))
                f.write("\n\n" + o.decode('ascii'))
                return
            elif in_val == 'N' or in_val == 'n':
                return
            else:
                print("Wrong argument! Try again")


def display(val):
    for i in range(4):
        print(int(val[i], 2), end='')
        f.write(str(int(val[i], 2)))
        if i < 3:
            print(".", end='')
            f.write(".")
    return


def start(value_entered):
    print("\nIP: " + value_entered[0], end='')
    f.write("IP: " + value_entered[0])
    mask = ""
    for i in range(4):
        mask += str(cidr_to_netmask(value_entered)[1][i])
        if i < 3:
            mask += "."
    print("\nMask: " + mask, end='')
    f.write("\nMask: " + mask)
    print("\nMask shortened: " + value_entered[1], end='')
    f.write("\nMask shortened: " + value_entered[1])

    adr_bin = network_bin(cidr_to_netmask(value_entered)[0], cidr_to_netmask(value_entered)[1])
    ip_address = adr_bin[0]
    sub_mask = adr_bin[1]

    print("\n\nNetwork address binary: ", end='')
    f.write("\n\nNetwork address binary: ")
    n_address = network_address(ip_address, sub_mask)
    print("\nNetwork address: ", end='')
    f.write("\nNetwork address: ")
    display(n_address)

    print("\n\nNetwork class: " + ip_class(ip_address))
    f.write("\n\nNetwork class: " + ip_class(ip_address))

    print("\nNetwork privacy status: " + is_private(value_entered[0]))
    f.write("\n\nNetwork privacy status: " + is_private(value_entered[0]))

    print("\nBroadcast address binary: ", end='')
    f.write("\n\nBroadcast address binary: ")
    b_address = broadcast_address(sub_mask, n_address)
    print("\nBroadcast address: ", end='')
    f.write("\nBroadcast address: ")
    display(b_address)

    print("\n\nFirst host in network binary: ", end='')
    f.write("\n\nFirst host in network binary: ")
    for i in range(4):
        if i != 3:
            print(n_address[i], end='')
            f.write(n_address[i])
            print(".", end='')
            f.write(".")
        elif i == 3:
            print(addition_bin("00000001", n_address[i]))
            f.write(addition_bin("00000001", n_address[i]))
    print("First host in network: ", end='')
    f.write("\nFirst host in network: ")
    for i in range(4):
        if i < 3:
            print(int(n_address[i], 2), end='')
            f.write(str(int(n_address[i], 2)))
            print(".", end='')
            f.write(".")
        elif i == 3:
            print(int(n_address[i], 2)+1, end='')
            f.write(str(int(n_address[i], 2)+1))

    print("\n\nLast host in network binary: ", end='')
    f.write("\n\nLast host in network binary: ")
    for i in range(4):
        if i != 3:
            print(b_address[i], end='')
            f.write(b_address[i])
            print(".", end='')
            f.write(".")
        elif i == 3:
            print(str(bin(int(b_address[i], 2)-1)).replace("0b", ""))
            f.write(str(bin(int(b_address[i], 2)-1)).replace("0b", ""))
    print("Last host in network: ", end='')
    f.write("\nLast host in network: ")
    for i in range(4):
        if i < 3:
            print(int(b_address[i], 2), end='')
            f.write(str(int(b_address[i], 2)))
            print(".", end='')
            f.write(".")
        elif i == 3:
            print(int(b_address[i], 2)-1, end='')
            f.write(str(int(b_address[i], 2)-1))

    max_host_number = max_hosts(value_entered[1])
    print("\n\nMaximal number of hosts in network: " + str(max_host_number), end='')
    f.write("\n\nMaximal number of hosts in network: " + str(max_host_number))

    is_host(value_entered[0], n_address, b_address)
    f.close()
    return


def subnet_calculator():
    print("\nWelcome to this simple subnet calculator.\nHope you will like it.\n")
    while True:
        print("\nMENU")
        print("   1. Use your local IP address and subnet mask")
        print("   2. Enter different IP address and subnet mask")
        print("   0. EXIT")
        choice = input('Your choice: ')
        if choice == '1':
            start(user_ip())
            return
        elif choice == '2':
            start(user_input_and_check())
            return
        elif choice == '0':
            print("\nThank you for using my calculator!\nBye Bye!")
            return
        else:
            print("\nThe option you chose does not exist at the moment but who knows what the future holds\n\n")


subnet_calculator()
