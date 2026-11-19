package codearts

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestChatStreamConvertsTextAndFinish(t *testing.T) {
	raw := "data: {\"text\":\"你\"}\n\n" +
		"data: {\"text\":\"你好\"}\n\n" +
		"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n" +
		"data: [DONE]\n\n"
	s := &ChatStream{
		model:  "GLM-5.2",
		body:   io.NopCloser(strings.NewReader(raw)),
		reader: bufio.NewReader(strings.NewReader(raw)),
	}
	var got strings.Builder
	for {
		chunk, err := s.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got.Write(chunk)
	}
	text := got.String()
	if !strings.Contains(text, `"content":"你"`) || !strings.Contains(text, `"content":"好"`) {
		t.Fatalf("deltas missing:\n%s", text)
	}
	if !strings.Contains(text, `"finish_reason":"stop"`) {
		t.Fatalf("finish chunk missing:\n%s", text)
	}
	if !strings.Contains(text, `"usage":{"completion_tokens":2`) {
		t.Fatalf("usage chunk missing:\n%s", text)
	}
	if !strings.HasSuffix(text, "data: [DONE]\n\n") {
		t.Fatalf("DONE missing:\n%s", text)
	}
}

func TestChatStreamAggregate(t *testing.T) {
	raw := "data: {\"text\":\"hello \"}\n\n" +
		"data: {\"text\":\"hello world\"}\n\n" +
		"data: {\"text\":\"hello world\",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\n\n" +
		"data: [DONE]\n\n"
	s := &ChatStream{
		model:  "GLM-5.2",
		body:   io.NopCloser(strings.NewReader(raw)),
		reader: bufio.NewReader(strings.NewReader(raw)),
	}
	obj, err := s.Aggregate()
	if err != nil {
		t.Fatal(err)
	}
	choices, _ := obj["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("choices = %#v", obj["choices"])
	}
	msg, _ := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "hello world" {
		t.Fatalf("content = %#v", msg["content"])
	}
	usage, _ := obj["usage"].(map[string]any)
	if usage["total_tokens"] != float64(3) {
		t.Fatalf("usage = %#v", usage)
	}
}
