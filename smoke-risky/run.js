const express = require("express");
const router = express.Router();

router.post("/run", (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

module.exports = router;
