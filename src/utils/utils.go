package utils

func MinInt (x int, y int) int {
	if x < y {
		return x
	}
	return y
}

func MinUInt (x uint, y uint) uint {
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
