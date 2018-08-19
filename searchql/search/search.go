package search

import (
	"fmt"
)

type SchedRecurByDay struct {
	Ord int
	Days map[string]struct{}
	Months map[string]struct{}
	Clock string
}

type SchedRecurByTime struct {
	N         int
	ClockLbl  string
	FromClock string
	ToClock   string
}

type OnSchedParseCb func(*SchedParseRes)

type SchedLex struct {
	S            string
	pos          int
	OnSchedParse OnSchedParseCb
	Itemchan     chan *SchedParseRes
	buf          []byte
}

func ParseSched(token string, cb OnSchedParseCb) int {
	return SearchParse(&SchedLex{S: token, OnSchedParse: func(res *SchedParseRes) {
		fmt.Println("Hello")
	}})
}

/*
func ToEasy(res *SchedParseRes) (byTime *SchedRecurByTime, byDay *SchedRecurByDay) {
	return
}
*/
