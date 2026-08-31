package main

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

type optionHelp struct {
	names        []string
	help         string
	defaultValue any
}

func printUsage(fs *flag.FlagSet, title string, options []optionHelp) {
	fmt.Fprintf(fs.Output(), "%s\n\nUsage:\n  %s [options]\n\nOptions:\n", title, fs.Name())
	for _, opt := range options {
		help := opt.help
		if value, ok := formatDefault(opt.defaultValue); ok {
			help = fmt.Sprintf("%s (default: %s)", help, value)
		}
		fmt.Fprintf(fs.Output(), "  %-34s %s\n", strings.Join(opt.names, ", "), help)
	}
}

func formatDefault(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "", false
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	case bool:
		return fmt.Sprintf("%t", v), true
	case int:
		return fmt.Sprintf("%d", v), true
	case float64:
		return fmt.Sprintf("%g", v), true
	case time.Duration:
		if v%time.Second == 0 {
			return fmt.Sprintf("%gs", v.Seconds()), true
		}
		return v.String(), true
	case []string:
		if len(v) == 0 {
			return "", false
		}
		return strings.Join(v, ","), true
	default:
		return fmt.Sprintf("%v", v), true
	}
}
