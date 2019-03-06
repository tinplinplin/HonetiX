#!/usr/bin/python

# Dependencias y librerias
import xml.etree.ElementTree as etree
import sys
import os.path

# Buscamos en el fichero el campo
archive = etree.parse(str(sys.argv[1]))
host = archive.findall("host")

# Para cada etiqueta <host>, leemos el campo address
for h in host:
    address = h.findall("address")

    # Comprobamos si cada direccion tiene mac asociada o no
    if len(address) == 2:
        ip = address[0].attrib["addr"]
        mac = address[1].attrib["addr"]
        print('host=' + ip + ' ' + 'mac=' + mac)
    else:
        ip = address[0].attrib["addr"]

    # Para cada etiqueta <port>, leemos los campos siguientes
    ports = h.find("ports")
    port = ports.findall("port")

    # Comprobamos si existe la etiqueta <port>
    if port is not None:
        i = 0
    # Leemos los campos que nos interesan de cada puerto
        while i < len(port):
            protocol = port[i].attrib["protocol"]
            port_id = port[i].attrib["portid"]
            status = port[i].find("state")
            state = status.attrib["state"]
            reason = status.attrib["reason"]
            service = port[i].find("service")
            service_name = service.attrib["name"]

            # Comprobamos si existe el campo product
            if 'product' in service.attrib:
                service_product = service.attrib["product"]

                # Comprobamos si existe el campo ostype
                if 'ostype' in service.attrib:
                    service_ostype = service.attrib["ostype"]

                    # Comprobamos si existe el campo version e imprimimos en funcion de los campos que hayamos encontrado
                    if 'version' in service.attrib:
                        service_version = service.attrib["version"]
                        print('host=' + ip + ' ' + 'protocol="' + protocol + '"' + ' ' + 'port_id=' + str(port_id) + ' ' + 'state_port=' + state + ' ' + 'reason_port="' + reason +
                              '"' + ' ' + 'service_name="' + service_name + '"' + ' ' + 'service_product="' + service_product + '"' + ' ' + 'service_ostype="' + service_ostype + '"')
                    else:
                        print('host=' + ip + ' ' + 'protocol="' + protocol + '"' + ' ' + 'port_id=' + str(port_id) + ' ' + 'state_port=' + state + ' ' + 'reason_port="' + reason +
                              '"' + ' ' + 'service_name="' + service_name + '"' + ' ' + 'service_product="' + service_product + '"' + ' ' + 'service_ostype="' + service_ostype + '"')
                # Si no existe el campo ostype
                else:
                    if 'version' in service.attrib:
                        service_version = service.attrib["version"]
                        print('host=' + ip + ' ' + 'protocol="' + protocol + '"' + ' ' + 'port_id=' + str(port_id) + ' ' + 'state_port=' + state + ' ' + 'reason_port="' + reason +
                              '"' + ' ' + 'service_name="' + service_name + '"' + ' ' + 'service_product="' + service_product + '"' + ' ' + 'service_version="' + service_version + '"')
                    else:
                        print('host=' + ip + ' ' + 'protocol="' + protocol + '"' + ' ' + 'port_id=' + str(port_id) + ' ' + 'state_port=' + state + ' ' +
                              'reason_port="' + reason + '"' + ' ' + 'service_name="' + service_name + '"' + ' ' + 'service_product="' + service_product + '"')
            # Si no existe el campo product
            else:
                print('host=' + ip + ' ' + 'protocol="' + protocol + '"' + ' ' + 'port_id=' + str(port_id) + ' ' +
                      'state_port=' + state + ' ' + 'reason_port="' + reason + '"' + ' ' + 'service_name="' + service_name + '"')
            i = i + 1
# Leemos el campo os
    operation_system = h.find("os")
    # Comprobamos si existen sistemas operativos
    if operation_system is not None:
        osmatch = operation_system.findall("osmatch")
        # Comprobamos si existe el campo osmatch
        if osmatch is not None:
            o = 0
            # Leemos los campos que nos interesan de cada sistema operativo
            while o < len(osmatch):
                osname = osmatch[o].attrib["name"]
                osclass = osmatch[o].find("osclass")
                # Comprobamos si existe el campo osclass
                if osclass is not None:
                    # Comprobamos si existe el campo type
                    if 'type' in osclass.attrib:
                        ostype = osclass.attrib["type"]
                        # Comprobamos si existe el campo osfamily
                        if 'osfamily' in osclass.attrib:
                            osfamily = osclass.attrib["osfamily"]
                            # Comprobamos si existe el campo vendor
                            if 'vendor' in osclass.attrib:
                                osvendor = osclass.attrib["vendor"]
                            # Comprobamos si existe el campo osgen
                            if 'osgen' in osclass.attrib:
                                osgen = osclass.attrib["osgen"]
                                # Comprobamos si existe el campo accuracy e imprimimos en funcion de los campos que hayamos encontrado
                                if 'accuracy' in osclass.attrib:
                                    accuracy = osclass.attrib["accuracy"]
                                    # Comprobamos si el porcentaje de acierto del sistema operativo es mayor del 95%
                                    if int(accuracy) > 95:
                                        print('host=' + ip + ' ' + 'osname="' + osname + '"' + ' ' + 'ostype="' + ostype + '"' + ' ' +
                                              'osvendor="' + osvendor + '"' + ' ' + 'osfamily="' + osfamily + '"' + ' ' + 'osgen="' + osgen + '"')
            o = o + 1
