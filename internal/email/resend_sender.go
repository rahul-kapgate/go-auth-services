package email

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/resend/resend-go/v4"
)

type VerificationMailer interface {
	SendVerificationOTP(
		ctx context.Context,
		to string,
		name string,
		code string,
		expiry time.Duration,
	) error
}

type ResendSender struct {
	client *resend.Client
	from   string
}

func NewResendSender(
	apiKey string,
	from string,
) (*ResendSender, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("RESEND_API_KEY is required")
	}

	if strings.TrimSpace(from) == "" {
		return nil, fmt.Errorf("RESEND_FROM is required")
	}

	client := resend.NewClient(apiKey)

	return &ResendSender{
		client: client,
		from:   from,
	}, nil
}

func (s *ResendSender) SendVerificationOTP(
	ctx context.Context,
	to string,
	name string,
	code string,
	expiry time.Duration,
) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	safeName := html.EscapeString(name)

	expiryMinutes := int(expiry.Minutes())
	if expiryMinutes < 1 {
		expiryMinutes = 1
	}

	htmlBody := fmt.Sprintf(`
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="max-width: 480px; margin: 30px auto;">
                <h2>Verify your email</h2>

                <p>Hello %s,</p>

                <p>
                    Thank you for creating an account.
                    Use the following OTP to verify your email address.
                </p>

                <div style="
                    background: #f4f4f4;
                    padding: 20px;
                    text-align: center;
                    font-size: 32px;
                    font-weight: bold;
                    letter-spacing: 8px;
                ">
                    %s
                </div>

                <p>This OTP expires in %d minutes.</p>

                <p>If you did not request this, you can ignore this email.</p>

                <p>Regards,<br/>Go Auth Service</p>
            </div>
        </body>
        </html>
    `, safeName, code, expiryMinutes)

	textBody := fmt.Sprintf(
		"Hello %s,\n\nYour email verification OTP is %s.\nIt expires in %d minutes.\n\nIf you did not request this, ignore this email.",
		name,
		code,
		expiryMinutes,
	)

	params := &resend.SendEmailRequest{
		From:    s.from,
		To:      []string{to},
		Subject: "Verify your email address",
		Html:    htmlBody,
		Text:    textBody,
	}

	_, err := s.client.Emails.SendWithContext(ctx, params)

	if err != nil {
		return fmt.Errorf("resend email delivery failed: %w", err)
	}

	return nil
}
