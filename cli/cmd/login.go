package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tomeksdev/NexusHub/cli/internal/client"
	"github.com/tomeksdev/NexusHub/cli/internal/config"
)

var (
	loginEmail  string
	loginNoSave bool
	// Intentionally no --password flag: passing it on the command line
	// leaks the password to process-listing tools. Use an interactive
	// prompt or an API key entry in the config file instead.
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate against the NexusHub API and cache the tokens",
	Long: `Prompts for email and password, obtains an access + refresh pair,
and stores them in the config file for subsequent commands.

When the account has 2FA enabled the command prompts for the 6-digit
authenticator code after the password check succeeds.

For unattended automation (cron, CI) prefer an API key. Set it by
editing the config file directly:

  api_key: <key issued via the UI>

API keys bypass the password + TOTP prompts and take precedence over
any cached tokens.`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginEmail, "email", "", "email address to log in as (prompted if omitted)")
	loginCmd.Flags().BoolVar(&loginNoSave, "no-save", false, "verify credentials but don't write the config file")
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, _ []string) error {
	cfgPath, err := config.Path(flagConfig)
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	cli := client.New(cfg, flagServer)

	email := loginEmail
	if email == "" {
		email, err = promptLine(cmd.OutOrStdout(), "Email: ")
		if err != nil {
			return err
		}
	}
	password, err := promptPassword(cmd.OutOrStdout(), "Password: ")
	if err != nil {
		return err
	}

	resp, err := cli.Login(email, password, "")
	if client.IsTOTPRequired(err) {
		code, perr := promptLine(cmd.OutOrStdout(), "Authenticator code: ")
		if perr != nil {
			return perr
		}
		resp, err = cli.Login(email, password, code)
	}
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	cfg.Email = email
	cfg.AccessToken = resp.AccessToken
	cfg.RefreshToken = resp.RefreshToken
	cfg.AccessExpiry = resp.AccessExpiresAt
	// Leave any existing api_key untouched — the precedence rule in
	// client.Do means a stale API key would shadow the tokens we just
	// stored. Operators who want to switch from API-key to bearer flow
	// should clear api_key explicitly in the config file.

	if loginNoSave {
		fmt.Fprintf(cmd.OutOrStdout(), "logged in as %s (role %s) — tokens not persisted\n", email, resp.Role)
		return nil
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "logged in as %s (role %s)\ntokens saved to %s\n", email, resp.Role, cfgPath)
	return nil
}

func promptLine(out interface{ Write([]byte) (int, error) }, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func promptPassword(out interface{ Write([]byte) (int, error) }, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	// Read raw bytes from /dev/tty when available so scripted
	// invocations that pipe a password through stdin still work via
	// the stdin fallback. os.Stdin.Fd() fails term.ReadPassword if it
	// isn't a terminal; we fall through to a regular ReadString then.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		fmt.Fprintln(out)
		return string(pw), nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return strings.TrimSpace(line), nil
}
