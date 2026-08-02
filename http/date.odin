package http

import "core:time"

/*
IMF-fixdate formatting, the only date format a server may emit (RFC 9110 5.6.7).

Formatting is done by hand rather than through a general time formatter because
the format is fixed-width and the output is written on every single response.
The server caches the result for one second, so this runs once per second rather
than once per request.
*/

DATE_LENGTH :: len("Mon, 02 Jan 2006 15:04:05 GMT")

@(rodata)
day_names := [?]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

@(rodata)
month_names := [?]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

/*
Writes an IMF-fixdate into `buf`, which must be at least DATE_LENGTH bytes.

Returns the formatted slice.
*/
date_write :: proc(buf: []byte, t: time.Time) -> string {
	assert(len(buf) >= DATE_LENGTH)

	year, month, day := time.date(t)
	hour, minute, second := time.clock_from_time(t)

	// `time.weekday` returns Sunday == 0, matching day_names.
	weekday := int(time.weekday(t))

	w := 0
	write_str :: proc(buf: []byte, w: ^int, s: string) {
		copy(buf[w^:], s)
		w^ += len(s)
	}
	write_2 :: proc(buf: []byte, w: ^int, v: int) {
		buf[w^]     = byte('0' + (v / 10) % 10)
		buf[w^ + 1] = byte('0' + v % 10)
		w^ += 2
	}

	write_str(buf, &w, day_names[weekday])
	write_str(buf, &w, ", ")
	write_2(buf, &w, day)
	buf[w] = ' '; w += 1
	write_str(buf, &w, month_names[int(month) - 1])
	buf[w] = ' '; w += 1

	buf[w]     = byte('0' + (year / 1000) % 10)
	buf[w + 1] = byte('0' + (year / 100) % 10)
	buf[w + 2] = byte('0' + (year / 10) % 10)
	buf[w + 3] = byte('0' + year % 10)
	w += 4

	buf[w] = ' '; w += 1
	write_2(buf, &w, hour)
	buf[w] = ':'; w += 1
	write_2(buf, &w, minute)
	buf[w] = ':'; w += 1
	write_2(buf, &w, second)
	write_str(buf, &w, " GMT")

	return string(buf[:w])
}
