const transporter = require("./mailer");

module.exports.sendResetPasswordEmail = async ({ to, token }) => {
  const link = `${process.env.FRONT_URL}/reset-password?token=${token}`;

  await transporter.sendMail({
    from: `"Auth App" <${process.env.SMTP_MAIL}>`,
    to,
    subject: "Reset your password",
    html: `
      <h2>Password reset</h2>
      <p>Click below to reset your password:</p>
      <a href="${link}">Reset password</a>
      <p>This link expires in 1 hour.</p>
    `,
  });
};
