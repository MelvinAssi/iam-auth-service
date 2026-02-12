const transporter = require("./mailer");

module.exports.sendResetPasswordEmail = async ({ to, token }) => {
  const link = `${process.env.FRONT_URL}/reset-password?token=${token}`;

  await transporter.sendMail({
    from: `"IAM Auth Service App" <${process.env.SMTP_MAIL}>`,
    to,
    subject: "Reset your password",
    html: `
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Password reset</title>
        </head>

        <body style="margin:0; padding:0; font-family:Arial, sans-serif;">

          <table width="100%" cellpadding="0" cellspacing="0" style="padding:20px;">
            <tr>
              <td align="center">

                <table width="600" cellpadding="0" cellspacing="0"
                       style="background-color:#ffffff; border-radius:10px; border:2px solid #090d1b; overflow:hidden;">

                  <!-- Header -->
                  <tr>
                    <td style="background-color:#19254d; color:#dbe0f2; padding:30px; text-align:center;">
                      <h1 style="margin:0; font-size:24px;">IAM Auth Service App</h1>
                    </td>
                  </tr>

                  <!-- Content -->
                  <tr>
                    <td style="padding:30px; color:#333333;">
                      <h2 style="margin-top:0; color:#465fb9;">Password reset</h2>

                      <p>You requested to reset your password. Click the button below to continue:</p>

                      <table cellpadding="0" cellspacing="0" style="margin:20px 0;">
                        <tr>
                          <td align="center">
                            <a href="${link}"
                               style="background-color:#4253bd;
                                      color:#ffffff;
                                      text-decoration:none;
                                      padding:15px 30px;
                                      border-radius:5px;
                                      font-weight:bold;
                                      display:inline-block;">
                              Reset password
                            </a>
                          </td>
                        </tr>
                      </table>

                      <p style="font-size:14px; color:#666666;">
                        This link expires in 1 hour.
                      </p>

                      <p style="font-size:13px; color:#999999;">
                        If you did not request a password reset, you can safely ignore this email.
                      </p>
                    </td>
                  </tr>

                </table>

              </td>
            </tr>
          </table>

        </body>
      </html>
    `,
  });
};
