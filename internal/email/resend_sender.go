package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

const resendAPIURL = "https://api.resend.com/emails"

type Sender interface {
	SendVerificationOTP(
		ctx context.Context,
		to string,
		otp string,
		expiresIn time.Duration,
	) error
}

type ResendSender struct {
	apiKey string
	from   string
	client *http.Client
}

type sendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text"`
}

type resendResponse struct {
	ID string `json:"id"`
}

type resendErrorResponse struct {
	Message string `json:"message"`
	Name    string `json:"name"`
}

func NewResendSender(
	apiKey string,
	from string,
) (*ResendSender, error) {
	apiKey = strings.TrimSpace(apiKey)
	from = strings.TrimSpace(from)

	if apiKey == "" {
		return nil, errors.New("RESEND_API_KEY is required")
	}

	if from == "" {
		return nil, errors.New("RESEND_FROM is required")
	}

	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("invalid RESEND_FROM address: %w", err)
	}

	return &ResendSender{
		apiKey: apiKey,
		from:   from,
		client: &http.Client{
			Timeout: 12 * time.Second,
		},
	}, nil
}

// SendVerificationOTP sends an email verification OTP.
func (s *ResendSender) SendVerificationOTP(
	ctx context.Context,
	to string,
	otp string,
	expiresIn time.Duration,
) error {
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("invalid recipient email: %w", err)
	}

	// Ensure only a six-digit OTP is accepted.
	if len(otp) != 6 {
		return errors.New("OTP must contain six digits")
	}

	for _, digit := range otp {
		if digit < '0' || digit > '9' {
			return errors.New("OTP must contain only digits")
		}
	}

	if expiresIn <= 0 {
		return errors.New("OTP expiry must be positive")
	}

	expiryMinutes := int(math.Ceil(expiresIn.Minutes()))

	htmlBody, textBody, err := buildOTPEmail(
		otp,
		expiryMinutes,
	)
	if err != nil {
		return fmt.Errorf("failed to build OTP email: %w", err)
	}

	payload := sendEmailRequest{
		From:    s.from,
		To:      []string{to},
		Subject: "Verify your email - Go Auth Service",
		HTML:    htmlBody,
		Text:    textBody,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode email request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		resendAPIURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to create email request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email through Resend: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(
		io.LimitReader(resp.Body, 1<<20),
	)
	if err != nil {
		return fmt.Errorf("failed to read Resend response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr resendErrorResponse

		_ = json.Unmarshal(responseBody, &apiErr)

		if apiErr.Message != "" {
			return fmt.Errorf(
				"Resend API error (%d): %s",
				resp.StatusCode,
				apiErr.Message,
			)
		}

		return fmt.Errorf(
			"Resend API returned status %d",
			resp.StatusCode,
		)
	}

	var result resendResponse

	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("failed to parse Resend response: %w", err)
	}

	if result.ID == "" {
		return errors.New("Resend response did not contain an email ID")
	}

	return nil
}

// buildOTPEmail creates the HTML and plain-text email templates.
func buildOTPEmail(
	otp string,
	expiryMinutes int,
) (string, string, error) {
	const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Verification</title>
</head>
<body style="margin:0;padding:30px;background:#f4f4f5;
font-family:Arial,sans-serif;color:#18181b;">

<div style="max-width:480px;margin:auto;padding:32px;
background:#ffffff;border-radius:12px;">

<h2 style="margin-top:0;">Verify your email</h2>

<p>Thank you for signing up with Go Auth Service.</p>

<p>Use the following verification code:</p>

<div style="margin:28px 0;padding:20px;text-align:center;
background:#f4f4f5;border-radius:8px;
font-size:32px;font-weight:bold;letter-spacing:8px;">
{{.OTP}}
</div>

<p>This code expires in {{.ExpiryMinutes}} minutes.</p>

<p style="color:#71717a;font-size:13px;">
If you didn't request this code, you can safely ignore this email.
</p>

</div>
</body>
</html>`

	tmpl, err := template.New("otp").Parse(htmlTemplate)
	if err != nil {
		return "", "", err
	}

	var htmlBuffer bytes.Buffer

	data := struct {
		OTP           string
		ExpiryMinutes int
	}{
		OTP:           otp,
		ExpiryMinutes: expiryMinutes,
	}

	if err := tmpl.Execute(&htmlBuffer, data); err != nil {
		return "", "", err
	}

	textBody := fmt.Sprintf(
		"Your Go Auth Service verification code is %s.\n\nIt expires in %d minutes. If you didn't request this code, ignore this email.",
		otp,
		expiryMinutes,
	)

	return htmlBuffer.String(), textBody, nil
}
