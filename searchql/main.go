package main

import (
	. "github.com/ligurio/search-query/search"
	"fmt"
)

//{"every 21 hrs from 06:30 to 08:30", 0, &SchedParseRes{C_RecurByTime, []RecurByTime{"every", 21, "hrs", []RecurByTime2{"from", "06:30", "to", "08:30"}}}},
func ToByTime(res *SchedParseRes) (byTime *SchedRecurByTime) {
	return
}

//{"312th sun of feb,jan,mar 17:23", 0, &SchedParseRes{C_RecurByDay, []RecurByDay{312, []Days{"sunday", nildays}, []RecurByDay2{"of", []Months{"february", []Months1{"january", "march"}}}, "17:23"}}},
func ToByDay(res *SchedParseRes) (byDay *SchedRecurByDay) {

	if (C_RecurByDay != res.Type) || (nil == res.Item) {
		return
	}
	e := new(SchedRecurByDay)
	e.Days = map[string]struct{}{}
	e.Months = map[string]struct{}{}
	byDay = e
	return
}

func main() {

	token := "every 3 secs from 06:30 to 08:30"
        ret := ParseSched(token, func(bytime *SchedParseRes) {
        })

        fmt.Println(token, ret)
}
