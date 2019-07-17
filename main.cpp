#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char *mac){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(const u_char *ip){
    printf("%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
}

void print_port(const u_char *port){
    printf("%d",(port[0]<<8)|port[1]);
}

void print_TCPdata(const u_char *data, unsigned int payload){
    unsigned int i;
    if (payload>10){ // maximum 10
        payload=10;
    }
    for (i=0; i<payload;i++){
        if(data[i] == 0x00 && data[i+1] == 0x00){//check padding
            printf(" padding value");
            break;
        }
        else{
            printf("%02x ",data[i]);
        }
    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) { // Ethernet header 14byte + IP header 20byte + TCP header 20 byte + Option(0~40 byte) + TCP Data
    struct pcap_pkthdr* header;
    const u_char* packet;
    unsigned int option_length, TCPpayload;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("eth.Dmac: ");
    print_mac(&packet[0]); //Ethernet header = Dmac 6 byte + Smac 6 byte + Ether type 2byte
    printf(" eth.Smac: ");
    print_mac(&packet[6]); // after Dmac 6 byte
    if (packet[12]==0x08&&(packet[13]==0x00)){ // Check Ether type is IP(08 00)
        printf(" ip.sip: ");
        print_ip(&packet[26]); // IP header = various fields(length, service ..) 9 byte + prot type 1 byte + checksum 2 byte + S ip 4 byte + D ip 4 byte
        printf(" ip.dip: ");
        print_ip(&packet[30]); //
        if (packet[23]==0x06){ // Check prot type is TCP(06)
            printf(" tcp.sport: ");
            print_port(&packet[34]); //TCP header = S port 2 byte + D port 2 byte + ....
            printf(" tcp.dport: ");
            print_port(&packet[36]);
            if(header->caplen > 54){ //if len is longer than essential header len
                option_length = (packet[46]-0x50)/4; // check option length in TCP header length(20 bytes + option bytes) , sub essential length(0x50==20 bytes) and translation values to bytes(ex : 0x60 = 24 bytes, 0x60 - 0x50 = 0x10 = 16, 16/4= 4 bytes)
                printf(" TCP data: ");
                if(option_length > 0 && header->caplen > (54 + option_length)){// if it exists options and total length > essential + option length, add offset
                    TCPpayload = header->caplen - 54 - option_length;
                    print_TCPdata(&packet[54+option_length],TCPpayload);// after header + option
                }
                else if(option_length<=0 ){
                    TCPpayload = header->caplen - 54;
                    print_TCPdata(&packet[54],TCPpayload); //if only exists essential header, no offset
                }


           }

    //        }
        }
        else{
            printf(" not TCP \n");
        }
    }
    else{
        printf(" not IP \n");
    }
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
