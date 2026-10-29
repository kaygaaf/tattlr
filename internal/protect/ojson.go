package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// node is a JSON value that keeps object key order, so editing a user's
// settings file only changes the lines we mean to change.
type node struct {
	obj *object
	arr []*node
	isA bool
	raw json.RawMessage // scalars, kept verbatim

	// src is the node's original text and canon its canonical form at
	// parse time. Unchanged nodes print as src, so the user's layout
	// survives and diffs only show what tattlr changed.
	src   []byte
	canon string
}

type object struct {
	keys []string
	vals map[string]*node
}

func newObj() *node { return &node{obj: &object{vals: map[string]*node{}}} }

func (n *node) get(k string) *node {
	if n == nil || n.obj == nil {
		return nil
	}
	return n.obj.vals[k]
}

func (n *node) set(k string, v *node) {
	if _, ok := n.obj.vals[k]; !ok {
		n.obj.keys = append(n.obj.keys, k)
	}
	n.obj.vals[k] = v
}

func (n *node) del(k string) {
	if _, ok := n.obj.vals[k]; !ok {
		return
	}
	delete(n.obj.vals, k)
	for i, kk := range n.obj.keys {
		if kk == k {
			n.obj.keys = append(n.obj.keys[:i], n.obj.keys[i+1:]...)
			break
		}
	}
}

func (n *node) str() string {
	if n == nil || n.raw == nil {
		return ""
	}
	var s string
	if json.Unmarshal(n.raw, &s) != nil {
		return ""
	}
	return s
}

func scalar(v any) *node {
	b, _ := json.Marshal(v)
	return &node{raw: b}
}

// fromMap builds an ordered object from alternating key, value pairs.
func fromPairs(kv ...any) *node {
	n := newObj()
	for i := 0; i+1 < len(kv); i += 2 {
		switch v := kv[i+1].(type) {
		case *node:
			n.set(kv[i].(string), v)
		default:
			n.set(kv[i].(string), scalar(v))
		}
	}
	return n
}

func parseJSON(b []byte) (*node, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return newObj(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	n, err := parseNode(dec, b)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON")
	}
	return n, nil
}

func parseNode(dec *json.Decoder, src []byte) (*node, error) {
	start := dec.InputOffset()
	n, err := parseValue(dec, src)
	if err != nil {
		return nil, err
	}
	text := bytes.TrimLeft(src[start:dec.InputOffset()], " \t\r\n,:")
	if n.obj != nil || n.isA {
		n.src = text
		n.canon = n.canonical()
	}
	return n, nil
}

func parseValue(dec *json.Decoder, src []byte) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := newObj()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				v, err := parseNode(dec, src)
				if err != nil {
					return nil, err
				}
				n.set(k, v)
			}
			_, err := dec.Token()
			return n, err
		case '[':
			n := &node{isA: true}
			for dec.More() {
				v, err := parseNode(dec, src)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, v)
			}
			_, err := dec.Token()
			return n, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		b, err := json.Marshal(t)
		return &node{raw: b}, err
	}
}

// render prints with two-space indents, the way Claude Code, Codex and
// Cursor write these files.
func (n *node) render() []byte {
	var b strings.Builder
	n.write(&b, "", true)
	b.WriteByte('\n')
	return []byte(b.String())
}

func (n *node) canonical() string {
	var b strings.Builder
	n.write(&b, "", false)
	return b.String()
}

func (n *node) write(b *strings.Builder, ind string, keep bool) {
	if keep && n.src != nil && n.canonical() == n.canon {
		b.Write(n.src)
		return
	}
	switch {
	case n.obj != nil:
		if len(n.obj.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range n.obj.keys {
			kb, _ := json.Marshal(k)
			b.WriteString(ind + "  " + string(kb) + ": ")
			n.obj.vals[k].write(b, ind+"  ", keep)
			if i < len(n.obj.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(ind + "}")
	case n.isA:
		if len(n.arr) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, v := range n.arr {
			b.WriteString(ind + "  ")
			v.write(b, ind+"  ", keep)
			if i < len(n.arr)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(ind + "]")
	default:
		var out bytes.Buffer
		if json.Indent(&out, n.raw, ind, "  ") == nil {
			b.Write(out.Bytes())
		} else {
			b.Write(n.raw)
		}
	}
}
