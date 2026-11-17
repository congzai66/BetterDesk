package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const agentVersion = "1.0.0"

func main() {
	defaultConfig := `C:\ProgramData\BetterDesk\managed-agent.json`
	if os.PathSeparator == '/' {
		defaultConfig = "/etc/betterdesk/managed-agent.json"
	}
	configPath := flag.String("config", defaultConfig, "path to managed agent JSON config")
	install := flag.Bool("install", false, "install and start the Windows service")
	uninstall := flag.Bool("uninstall", false, "stop and remove the Windows service")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(agentVersion)
		return
	}
	exePath, err := os.Executable()
	if err != nil && (*install || *uninstall) {
		log.Fatal(err)
	}
	if *install {
		if err := installPlatformService(exePath, *configPath); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *uninstall {
		if err := uninstallPlatformService(); err != nil {
			log.Fatal(err)
		}
		return
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(cfg.RustDeskPath); err != nil {
		log.Fatalf("RustDesk executable is not accessible: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0700); err != nil {
		log.Fatal(err)
	}
	agent, err := NewCredentialAgent(cfg.StatePath, &RustDeskPasswordApplier{Path: cfg.RustDeskPath})
	if err != nil {
		log.Fatal(err)
	}
	defer agent.Close()
	client := &CDAPClient{cfg: cfg, agent: agent}
	if err := runPlatform(client.Run); err != nil {
		log.Fatal(err)
	}
}

func runContext(run func(context.Context) error) error {
	return run(context.Background())
}
