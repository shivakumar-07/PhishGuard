/* PhishGuard Scam Intelligence — identifies WHAT KIND of scam a message is
 * and tells the user exactly what to do about it. Runs entirely on-device.
 *
 * Categories cover the fraud families that cost people real money every
 * day: bank/KYC blocks, OTP theft, lottery/prize lures, job-fee scams,
 * investment "doubling", courier/customs fees, utility disconnection
 * threats, tech-support cold calls, and sextortion/romance pressure.
 */

export const SCAM_CATEGORIES = [
  {
    id: "otp_theft",
    label: "OTP / verification-code theft",
    keywords: ["share otp", "share the otp", "tell me the otp", "otp received",
               "verification code", "read out the code", "6 digit code",
               "code sent to your phone", "give me the code"],
    advice: [
      "Never share an OTP with anyone — not even someone claiming to be your bank, courier, or a buyer.",
      "An OTP is the key to YOUR money. Banks and companies never ask for it.",
      "If you already shared one, call your bank's official number immediately and block the card/account.",
    ],
  },
  {
    id: "banking_kyc",
    label: "Bank / KYC suspension scam",
    keywords: ["kyc", "re-kyc", "kyc update", "kyc expire", "account suspended",
               "account will be blocked", "account has been blocked", "net banking suspended",
               "pan card update", "aadhaar update", "debit card blocked",
               "credit card blocked", "bank account verification", "yono"],
    advice: [
      "Banks NEVER send KYC links by SMS/WhatsApp. KYC happens in the branch or the official app only.",
      "Do not click the link. Open your bank's app directly or call the number printed on your card.",
      "Report the message to your bank and to the cybercrime portal (cybercrime.gov.in / 1930 in India).",
    ],
  },
  {
    id: "courier_customs",
    label: "Courier / customs-fee scam",
    keywords: ["customs fee", "customs duty", "parcel held", "package held",
               "parcel is on hold", "redelivery", "delivery attempt failed",
               "address is incomplete", "pay a small fee", "clearance fee",
               "your package could not be delivered", "shipment pending"],
    advice: [
      "Couriers never collect customs or redelivery fees through payment links.",
      "If you are expecting a parcel, track it ONLY on the courier's official website with your tracking number.",
      "Never pay 'small fees' via UPI/links — that's the whole scam, and it often escalates.",
    ],
  },
  {
    id: "lottery_prize",
    label: "Lottery / prize scam",
    keywords: ["you have won", "congratulations you won", "lottery", "lucky draw",
               "prize money", "claim your prize", "jackpot", "kbc", "lucky winner",
               "gift card won", "cash prize", "crore lottery"],
    advice: [
      "You cannot win a lottery you never entered. The 'prize' is bait for fees and bank details.",
      "Any prize that asks for a processing fee, tax, or OTP first is a scam, always.",
      "Block the sender. Do not reply — replying marks your number as active.",
    ],
  },
  {
    id: "job_offer",
    label: "Job-offer / task scam",
    keywords: ["work from home", "earn daily", "part time job", "online job",
               "registration fee", "joining fee", "security deposit", "easy income",
               "per day salary", "telegram job", "like videos and earn",
               "simple tasks", "weekly payout", "hiring immediately no interview"],
    advice: [
      "Real employers never charge registration, joining, or training fees — ever.",
      "'Earn by liking videos / simple tasks' always ends with you depositing money you never get back.",
      "Verify any company on its official careers page; ignore Telegram/WhatsApp 'HR' contacts.",
    ],
  },
  {
    id: "investment",
    label: "Investment / trading scam",
    keywords: ["guaranteed returns", "double your money", "triple your money",
               "trading tips", "stock tips", "crypto investment", "forex trading",
               "100% profit", "daily profit", "investment plan", "high returns",
               "sure shot", "insider tips", "join our vip group"],
    advice: [
      "Guaranteed or daily returns do not exist in real markets. 'Guaranteed' = scam.",
      "Scammers show fake profit dashboards and let you withdraw once — then take everything.",
      "Invest only through SEBI/FCA-registered platforms you found yourself, never via tips groups.",
    ],
  },
  {
    id: "utility",
    label: "Electricity / utility disconnection scam",
    keywords: ["electricity bill", "power will be disconnected", "electricity disconnected tonight",
               "bill not updated", "bill overdue", "update your bill", "electricity officer",
               "gas connection blocked", "water bill pending"],
    advice: [
      "Utilities send disconnection notices on bills, not WhatsApp messages from personal numbers.",
      "Check your dues ONLY in the official electricity-board app or website.",
      "Never call the mobile number in the message — that 'officer' is the scammer.",
    ],
  },
  {
    id: "tech_support",
    label: "Tech-support / remote-access scam",
    keywords: ["your computer is infected", "virus detected", "microsoft support",
               "windows support", "call our support", "anydesk", "teamviewer",
               "quick support", "remote access", "screen share", "install this app to fix"],
    advice: [
      "Microsoft, Google, and banks never call you about viruses or ask to install AnyDesk/TeamViewer.",
      "Remote-access apps give scammers full control of your device and bank apps — never install on request.",
      "If something was installed, disconnect from the internet and uninstall it immediately.",
    ],
  },
  {
    id: "sextortion",
    label: "Blackmail / sextortion pressure",
    keywords: ["your video", "recorded you", "webcam footage", "will send to your contacts",
               "pay in bitcoin", "compromising", "i know what you did", "your private photos"],
    advice: [
      "These messages are mass-sent bluffs in almost all cases. Do not pay — paying invites more demands.",
      "Do not reply. Take screenshots as evidence, block, and report to the cybercrime portal.",
      "If a real person is threatening you, tell someone you trust and go to the police — you are the victim here.",
    ],
  },
  {
    id: "impersonation",
    label: "Family-emergency / impersonation scam",
    keywords: ["i lost my phone", "this is my new number", "stuck and need money",
               "send money urgently", "hospital emergency send", "papa send money",
               "mom i need money", "accident need money"],
    advice: [
      "'New number + urgent money' is a classic impersonation. Verify by CALLING the person's old number.",
      "Ask something only the real person would know before even continuing the chat.",
      "Never send money based on a chat message alone, however emotional it sounds.",
    ],
  },
];

/** Analyze message text -> {category|null, label, hits[], advice[], boost}. */
export function analyzeScam(subject, body) {
  const text = `${subject || ""} ${body || ""}`.toLowerCase().replace(/\s+/g, " ");
  let best = null;
  for (const cat of SCAM_CATEGORIES) {
    const hits = cat.keywords.filter((k) => text.includes(k));
    if (!hits.length) continue;
    const strength = hits.length;
    if (!best || strength > best.strength) best = { cat, hits, strength };
  }
  if (!best || (best.strength < 2 && best.cat.id !== "otp_theft" && best.cat.id !== "sextortion"))
    return { category: null, boost: 0 };
  return {
    category: best.cat.id,
    label: best.cat.label,
    hits: best.hits.slice(0, 5),
    advice: best.cat.advice,
    boost: Math.min(6 + 4 * best.strength, 18),
  };
}
