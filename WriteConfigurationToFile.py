import uuid
import os

a = uuid.uuid3(uuid.NAMESPACE_DNS, 'foo')
print(a)

# A list of reals to make sure that the object is real and not other parameter (when attaching real to group).
reals_list = []
group_list = []
#A list of combined SSL policies (FE & BE)
#ssl_policy_dict = {}

#A list of combined SSL policies (FE & BE)
#VIP_IPs = []


CitrixService_to_AlteonService = {
    "SSL": "https",
    "HTTP": "http",
    "TCP": "basic-slb",
    "UDP": "basic-slb",
    "SSL_BRIDGE": "https",
    "ANY": "ip",
    "DNS": "dns",
    "FTP": "ftp"
}

rport_from_realGroup = {
}

monitor_mapping = {
    "tcps": "sslhtls",
    "PING": "icmp",
    "TCP": "tcp",
    "tcp": "tcp",
    "HTTP": "http"
}

RealID_to_RealIP_mapping = {
}

# Clear file config to avoid duplicate configuration
CAT_dir = 'C:\\Users\yehudap\Desktop\CAT\\'
arr = os.listdir(CAT_dir)
for i in arr:
    if i != 'Citrix.txt':
        os.remove(CAT_dir + i)

ParsedLines = open(CAT_dir + "ParsedLines.txt", "w")
CitrixFile = CAT_dir + "Citrix.txt"


def compare_conf(line_to_compare):
    with open(CAT_dir + "ParsedLines.txt") as file:
        for line in file:
            line = line.rstrip()
            if line_to_compare == line:
                break
        else:  # not found, we are at the eof
            ParsedLines.write(line_to_compare + "\n")  # append missing data
            #print(line_to_compare)
            ParsedLines.flush()


def get_td(line, element, type):
    if "-td" in line:
        td = line.split("-td ")[1]
        td = td[0]
        print(td)
        return td
    elif type == "SSL":
            with open(CitrixFile) as file1:
                for line_from_Citrix in file1:
                    line_from_Citrix = line_from_Citrix.rstrip()
                    if line_from_Citrix.startswith("set ssl vserver") and "-sslProfile " + element in line_from_Citrix:
                        virt_from_attaching_ssl_policy = line_from_Citrix.split()[3]
                        with open(CitrixFile) as file2:
                            for line_from_Citrix2 in file2:
                                line_from_Citrix2 = line_from_Citrix2.rstrip()
                                if line_from_Citrix2.startswith("add lb vserver"):
                                    virt_from_creating_virt = line_from_Citrix2.split()[3]
                                    if virt_from_creating_virt == virt_from_attaching_ssl_policy:
                                        td = line_from_Citrix2.split("-td ")[1]
                                        td = td[0]
                                        print(td)
                                        return td



# cert_dir = CAT_dir + "certs"
# arr = os.listdir(cert_dir)
# for i in arr:
#     if i.endswith('.pem') or i.endswith('.crt') or i.endswith('.key'):
#
#
        #print(i)
        # file = open(cert_dir + i)

        # file_contents = file.read()
        #print(file_contents)

        # search_cert_word = "BEGIN CERTIFICATE"
        # search_key_word = "BEGIN PRIVATE KEY"
        #
        # if search_cert_word in file_contents:
        #     print(i + " is a CERTIFICATE")
        #     AlteonConfiguration.write("/c/slb/ssl/certs/cert " + i + "\n")
        #     AlteonConfiguration.write("/c/slb/ssl/certs/import cert " + i + " text" + "\n")
        #     AlteonConfiguration.write(file_contents)
        #     AlteonConfiguration.write("\n")
        #
        # elif search_key_word in file_contents:
        #     print(i + " is a KEY")
        #     AlteonConfiguration.write("/c/slb/ssl/certs/key " + i + "\n")
        #     AlteonConfiguration.write("/c/slb/ssl/certs/import key " + i + " text" + "\n")
        #     AlteonConfiguration.write(file_contents)
        #     AlteonConfiguration.write("\n")



with open(CitrixFile) as file:
    for line in file:
        print(line.rstrip())
        line = line.rstrip()
        # print(line1)

        # ================  Real Creation ================
        if (line.startswith('add server')):
            # print("True")
            RealID = (line.split()[2])
            RealIP = (line.split()[3])
            print(RealID)
            print(RealIP)

            # For file
            element = RealID
            type = "Real"

            td = get_td(line, element, type)
            filePath = CAT_dir + "%s.txt" % ("td_" + str(td))
            Alteon_config = open(filePath, "a")

            Alteon_config.write("/c/slb/real " + RealIP + "\n")
            Alteon_config.write("\tena\n")
            Alteon_config.write("\tipver v4\n")
            Alteon_config.write("\trip " + RealIP + "\n")

            real_description, sep, tail = RealID.partition('_')
            real_description = real_description[0:31]
            
            Alteon_config.write("\tname " + real_description + "\n")
            reals_list.append(RealID)
            RealID_to_RealIP_mapping[RealID] = RealIP

            compare_conf(line)

            with open(CitrixFile) as file_to_get_port:
                for line_to_get_port in file_to_get_port:
                    #print(line_to_get_port.rstrip())
                    line_to_get_port = line_to_get_port.rstrip()
                    # print(line1)

                    # ================  Real Creation ================
                    if (line_to_get_port.startswith('bind serviceGroup')):
                        RealID_from_bind_line = (line_to_get_port.split()[3])
                        if RealID_from_bind_line == RealID:
                            try:
                                RealPort = (line_to_get_port.split()[4])

                                #Alteon_config.write("\taddport " + RealPort + "\n")

                                compare_conf(line_to_get_port)

                            except IndexError:
                                print("port is not defined")
        # ================  Group Creation ================

        if (line.startswith('add serviceGroup')):
            # print("True")
            GroupID = (line.split()[2])
            print(GroupID)


            group_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, GroupID)
            group_uuid = str(group_uuid)
            group_uuid = group_uuid.upper()

            element = GroupID
            type = "Group"

            td = get_td(line, element, type)
            filePath = CAT_dir + "%s.txt" % ("td_" + str(td))
            Alteon_config = open(filePath, "a")

            Alteon_config.write("/c/slb/group " + group_uuid + "\n")

            group_description, sep, tail = GroupID.partition('_')
            group_description = group_description[0:31]

            Alteon_config.write("\tname " + group_description + "\n")
            Alteon_config.write("\tipver v4\n")
            group_list.append(GroupID)

            compare_conf(line)

            with open(CitrixFile) as file_for_attach_real:
                for line_for_attach_real in file_for_attach_real:
                    line_for_attach_real = line_for_attach_real.rstrip()
                    #print(line_for_attach_real)
                    if (line_for_attach_real.startswith('bind serviceGroup')):
                        #print("line_for_attach_real: " + line_for_attach_real)
                        GroupID_from_attach_real = (line_for_attach_real.split()[2])
                        #print("GroupID_from_attach_real: " + GroupID_from_attach_real)
                        element_to_check = (line_for_attach_real.split()[3])
                        if GroupID_from_attach_real == GroupID:
                            if (element_to_check in reals_list):
                                try:
                                    rport_from_realGroup_line = (line_for_attach_real.split()[4])
                                    if rport_from_realGroup_line != "-weight":
                                        rport_from_realGroup[GroupID_from_attach_real] = rport_from_realGroup_line
                                except:
                                    print("port is not defined")
                                Alteon_config.write("\tadd " + RealID_to_RealIP_mapping[element_to_check] + "\n")

                                compare_conf(line_for_attach_real)



                            elif (element_to_check == "-monitorName"):
                                print(element_to_check + " Is a Monitor Setting")
                                Monitor_Name = (line_for_attach_real.split()[4])

                                if Monitor_Name in monitor_mapping:
                                    Monitor_Name = monitor_mapping[Monitor_Name]
                                    print("Monitor is " + Monitor_Name + "and it exists in dict")
                                    Alteon_config.write("\thealth " + Monitor_Name + "\n\n")

                                    compare_conf(line_for_attach_real)
                                else:
                                    #Monitor_Name = "tcp"
                                    print("Monitor is " + Monitor_Name + "and NOT exists in dict")
                                    Alteon_config.write("\thealth " + Monitor_Name + "\n\n")


        # ================  Add SSL Policy ================
        if (line.startswith('add ssl profile')):
            # print("True")
            SSL_Policy_ID = (line.split()[3])
            print(SSL_Policy_ID)

            search_Client_word = "Client"

            if search_Client_word in SSL_Policy_ID:
                ssl_profile = SSL_Policy_ID.replace('Client', '')
                ssl_profile = ssl_profile.replace('__', '_')

                element = SSL_Policy_ID
                type = "SSL"

                td = get_td(line, element, type)
                filePath = CAT_dir + "%s.txt" % ("td_" + str(td))
                Alteon_config = open(filePath, "a")

                Alteon_config.write("/c/slb/ssl/sslpol " + ssl_profile + "\n")
                Alteon_config.write("\tname " + ssl_profile + "\n")
                Alteon_config.write("\tconvert disabled\n")
                Alteon_config.write("\tena\n")
                Alteon_config.write("/c/slb/ssl/sslpol " + ssl_profile + "/backend" + "\n")
                Alteon_config.write("\tssl enabled\n\n")

                compare_conf(line)

                print(ssl_profile + " Client word has been removed")
                #for_checking = SSL_Policy_ID.replace('Client', 'Server')


                #with open(CitrixFile) as file_ssl_policy_mode:
                    #for line_ssl_policy_mode in file_ssl_policy_mode:
                        #line_ssl_policy_mode = line_ssl_policy_mode.rstrip()

                        #if (line_ssl_policy_mode.startswith('add ssl profile ' + for_checking)):
                            #print("=========================X " + line_ssl_policy_mode)


                            #AlteonConfiguration.write("/c/slb/ssl/sslpol " + ssl_profile + "\n")
                            #AlteonConfiguration.write("\tname " + ssl_profile + "\n")
                            #AlteonConfiguration.write("\tconvert disabled\n")
                            #AlteonConfiguration.write("\tena\n")
                            #AlteonConfiguration.write("/c/slb/ssl/sslpol " + ssl_profile + "/backend" + "\n")
                            #AlteonConfiguration.write("\tssl enabled\n\n")

                            #compare_conf(line_ssl_policy_mode)
        # ================  Add VIPs ================
        if (line.startswith('add lb vserver')):
            VIP_name = (line.split()[3])
            Service_name = (line.split()[4])
            VIP_IP = (line.split()[5])
            VIP_port = (line.split()[6])
            print("---------------------------------------" + VIP_name)
            print(VIP_port)
            if VIP_port == "*":
                VIP_port = "1"
            print(VIP_IP)
            print("Service is: " + Service_name)
            #VIP_IPs.append(VIP_IP)

            create_virt = 1
            if Service_name == "HTTP":
                with open(CitrixFile) as file:
                    for line_for_http in file:
                        #print(line_for_http.rstrip())
                        line_for_http = line_for_http.rstrip()
                        if (line_for_http.startswith('bind lb vserver ' + VIP_name + " -policyName http_to_https_redirect_policy")):
                            #if "-policyName http_to_https_redirect_policy" in line_for_http:
                            print("HTTP virt will redirect to HTTPS")
                            create_virt = 0

            if create_virt == 1 or Service_name != "HTTP":

                VIP_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, VIP_name)
                VIP_uuid = str(VIP_uuid)
                VIP_uuid = VIP_uuid.upper()

                element = VIP_name
                type = "VIP"

                td = get_td(line, element, type)
                filePath = CAT_dir + "%s.txt" % ("td_" + str(td))
                Alteon_config = open(filePath, "a")

                Alteon_config.write("/c/slb/virt " + VIP_uuid + "\n")
                Alteon_config.write("\tena\n")
                Alteon_config.write("\tipver v4\n")
                Alteon_config.write("\tvip " + VIP_IP + "\n")
                Alteon_config.write("\trtsrcmac ena\n")

                vip_description, sep, tail = VIP_name.partition('_')
                Alteon_config.write("\tvname " + vip_description + "\n")

                service = CitrixService_to_AlteonService[Service_name]
                print("service is " + service)

                Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "\n")

                compare_conf(line)
                with open(CitrixFile) as file1:
                    for line1 in file1:
                        line1 = line1.rstrip()
                        if (line1.startswith('bind lb vserver')):

                            print(line1)
                            Virt_from_bind_group = (line1.split()[3])
                            group = (line1.split()[4])
                            if Virt_from_bind_group == VIP_name and group in group_list:
                                Alteon_config.write("\tapplicid " + vip_description + ":" + VIP_port + "\n")
                                compare_conf(line1)

                                group_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, group)
                                group_uuid = str(group_uuid)
                                group_uuid = group_uuid.upper()
                                Alteon_config.write("\tgroup " + group_uuid + "\n")
                                
                                compare_conf(line1)
                                if Service_name == "UDP":
                                    Alteon_config.write("\tprotocol udp " + "\n")
                                    compare_conf(line1)

                                if Service_name == "HTTP":
                                    Alteon_config.write("\tdbind forceproxy " + "\n")
                                    Alteon_config.write("\tnonhttp ena " + "\n")
                                    compare_conf(line1)


                                with open(CitrixFile) as file2:
                                    for line2 in file2:
                                        line2 = line2.rstrip()
                                        if (line2.startswith('add serviceGroup')):
                                            print(line2)
                                            group_from_group_line = (line2.split()[2])
                                            if group_from_group_line == group:
                                                try:
                                                    rport = rport_from_realGroup[group_from_group_line]

                                                    if str(rport) == "*":
                                                        rport = "1"
                                                    Alteon_config.write("\trport " + rport + "\n")
                                                    #if "-usip NO" in line2:
                                                    #    Alteon_config.write("\tdbind forceproxy \n")

                                                    compare_conf(line2)
                                                except:
                                                    print("port is not defined")

                                                with open(CitrixFile) as file3:
                                                    for line3 in file3:
                                                        line3 = line3.rstrip()
                                                        if (line3.startswith('set ssl vserver')):
                                                            print(line3)
                                                            virt_ssl = (line3.split()[3])
                                                            if virt_ssl == VIP_name:
                                                                Alteon_config.write("\tdbind forceproxy \n")
                                                                Alteon_config.write("\tnonhttp ena " + "\n")

                                                                compare_conf(line3)


                                                if "-persistenceType" in line and "-persistenceType NONE" not in line and "-timeout" in line:
                                                    print("====================== " + line)
                                                    get_timeout_amount = (line.split("-timeout")[1])
                                                    get_timeout_amount = (get_timeout_amount.split()[0])
                                                    print("persistence timeout is: " + get_timeout_amount)
                                                    int_tmout = int(get_timeout_amount)
                                                    if int(get_timeout_amount) % 2 != 0:
                                                        int_tmout = int(get_timeout_amount)
                                                        int_tmout += 1
                                                        print(int_tmout)
                                                    Alteon_config.write("\tptmout " + str(int_tmout) + "\n")
                                                    compare_conf(line)


                                                if "-cltTimeout" in line2:
                                                    index = (line2.split("-cltTimeout ")[1])
                                                    print("AAAAAAAAAAAAAAAAAAAAA", index)
                                                    timeout_value = (index.split()[0])
                                                    print("BBBBBBBBBBBBBBBBB", timeout_value)
                                                    if int(timeout_value) >= 600:
                                                        timeout_value_in_minute = int(timeout_value) / 60
                                                        print (int(timeout_value_in_minute))
                                                        if int(timeout_value_in_minute) % 2 != 0:
                                                            timeout_value_in_minute += 1
                                                            print(int(timeout_value_in_minute))


                                                    if "-svrTimeout" in line2:
                                                        index = (line2.split("svrTimeout ")[1])
                                                        print("AAAAAAAAAAAAAAAAAAAAA", index)
                                                        timeout_value_svr = (index.split()[0])
                                                        print("BBBBBBBBBBBBBBBBB", timeout_value_svr)
                                                        if int(timeout_value_svr) >= 600:
                                                            if int(timeout_value_svr) > int(timeout_value):
                                                                timeout_value_in_minute = int(timeout_value_svr) / 60
                                                                print (int(timeout_value_in_minute))
                                                                if int(timeout_value_in_minute) % 2 != 0:
                                                                    timeout_value_in_minute += 1
                                                                    print(int(timeout_value_in_minute))
                                                                Alteon_config.write("\ttmout " + str(int(timeout_value_in_minute)) + "\n")

                                                                compare_conf(line2)
                                                            else:
                                                                Alteon_config.write("\ttmout " + str(int(timeout_value_in_minute)) + "\n")
                                                                compare_conf(line2)


                                                    else:
                                                        Alteon_config.write("\ttmout " + str(int(timeout_value_in_minute)) + "\n")
                                                        compare_conf(line2)




                                                if "-usip NO" in line2:
                                                    Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "/pip" + "\n")
                                                    Alteon_config.write("\tmode nwclss " + "\n")
                                                    Alteon_config.write("\tnwclss v4 AAAA persist client " + "\n")
                                                    compare_conf(line2)

                                                if "-cip ENABLED X-Forwarded-For" in line2 and (service == "http" or service == "https") and (Service_name == "SSL" or Service_name == "HTTP"):
                                                    Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "/http" + "\n")
                                                    Alteon_config.write("\txforward ena " + "\n")
                                                    compare_conf(line2)

                                                with open(CitrixFile) as file4:
                                                    for line4 in file4:
                                                        line4 = line4.rstrip()
                                                        if (line4.startswith('bind ssl vserver')) and "-CA" not in line4:
                                                            print(line4)
                                                            virt_ssl = (line4.split()[3])
                                                            print("SSSSSSSSSSSSSSSSSSLLLLLLLLLLLLLLLLLLLLLLLLL " + virt_ssl)
                                                            if virt_ssl == VIP_name:
                                                                Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "/ssl" + "\n")
                                                                certName = (line4.split()[5])
                                                                Alteon_config.write("\tsrvrcert cert "+ certName + "\n")
                                                                compare_conf(line4)

                                                                with open(CitrixFile) as file5:
                                                                    for line5 in file5:
                                                                        line5 = line5.rstrip()
                                                                        if (line5.startswith('set ssl vserver')):
                                                                            print(line5)
                                                                            virt_ssl_policy = (line5.split()[3])
                                                                            ssl_policy = (line5.split()[5])
                                                                            print("ssl policy " + ssl_policy)
                                                                            if virt_ssl_policy == VIP_name:

                                                                                ssl_policy = ssl_policy.replace('Client','')
                                                                                ssl_policy = ssl_policy.replace('__', '_')
                                                                                ssl_policy = ssl_policy
                                                                                print(ssl_policy + " Client word has been removed")
                                                                                Alteon_config.write("\tsslpol " + ssl_policy + "\n")
                                                                                compare_conf(line2)
                if "-persistenceType COOKIEINSERT" in line:
                    Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "/pbind cookie insert" + "\n")
                    compare_conf(line)

                elif "-persistenceType SOURCEIP " in line:
                    Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "/pbind clientip" + "\n")
                    compare_conf(line)

                elif "-persistenceType SSLSESSION" in line:
                    Alteon_config.write("/c/slb/virt " + VIP_uuid + "/service " + VIP_port + " " + service + "/pbind ssid" + "\n")
                    compare_conf(line)



#Write the None Parsed lines to the new file
ParsedLines.close

ParsedLines = CAT_dir + "ParsedLines.txt"
NoneParsedLines = open(CAT_dir + "NoneParsedLines.txt", "w")

with open(CitrixFile) as file1:
    for line_from_Citrix in file1:
        line_from_Citrix = line_from_Citrix.rstrip()
        with open(ParsedLines) as file2:
            for line_from_parsed in file2:
                line_from_parsed = line_from_parsed.rstrip()
                if line_from_parsed == line_from_Citrix:
                    print(line_from_parsed + " exists")
                    break
            else:
                print(line_from_Citrix + " not exists")
                NoneParsedLines.write(line_from_Citrix + "\n")
