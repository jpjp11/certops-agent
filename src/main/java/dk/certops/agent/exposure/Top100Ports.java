package dk.certops.agent.exposure;

import java.util.List;

public final class Top100Ports {

    private Top100Ports() {}

    public static final List<Integer> TOP_100 = List.of(
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 179, 199, 443, 445, 465, 514, 515, 548, 554,
            587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026,
            1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900,
            2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
            4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
            5666, 5800, 5900, 5985, 5986, 6000, 6001, 6379, 6646, 7070,
            7443, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090,
            9100, 9200, 9443, 9999, 10000, 11211, 27017, 27018, 28017, 32768,
            49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161
    );

    public static final List<Integer> TOP_50 = TOP_100.subList(0, 50);

    public static final List<Integer> TLS_PORTS = List.of(
            443, 465, 636, 853, 990, 993, 995, 5986, 7443, 8443, 9443
    );

    public static final List<Integer> HTTP_PORTS = List.of(
            80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9090, 9443
    );

    public static final List<Integer> BANNER_PORTS = List.of(
            21, 22, 25, 110, 143, 587
    );
}
