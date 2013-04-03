package utils

import "fmt"

func MinInt(x int, y int) int {
    if x < y {
        return x
    }
    return y
}

func MinUInt(x uint, y uint) uint {
    if x < y {
        return x
    }
    return y
}

func DecodeMac(pkt []byte) uint64 {
    mac := uint64(0)
    for i := uint(0); i < 6; i++ {
        mac = (mac << 8) + uint64(pkt[i])
    }
    return mac
}

func EncodeMac(mac uint64) string {
    return fmt.Sprintf("%x:%x:%x:%x:%x:%x",
        byte(mac>>40),
        byte(mac>>32),
        byte(mac>>24),
        byte(mac>>16),
        byte(mac>>8),
        byte(mac),
    )
}

func EncodeIp(ip uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        byte(ip>>24),
        byte(ip>>16),
        byte(ip>>8),
        byte(ip),
    )
}
