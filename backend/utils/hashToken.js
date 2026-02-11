module.exports = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};
