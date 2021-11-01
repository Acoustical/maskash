package slr1

import (
	"bufio"
	"log"
	"os"
	"testing"
)

func TestSLR(t *testing.T) {
	table, err := os.OpenFile("table.out", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
		return
	}
	tb := bufio.NewWriter(table)
	defer table.Close()
	reader, err := os.Open("test.txt")
	r := bufio.NewReader(reader)
	parser := new(Parser).New(r)
	parser.Print(tb)
}
