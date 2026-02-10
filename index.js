const crypto = require("crypto");
const WebSocket = require("ws");
const QRCode = require("qrcode");

const remoteAuthGatewayUrl = "wss://remote-auth-gateway.discord.gg/?v=2";

// RSA 키 쌍 생성
const rsaKeyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// 공개 키를 DER 형식으로 내보내기
const publicKey = rsaKeyPair.publicKey.export({
  type: "spki",
  format: "der",
});

// WebSocket 연결 설정
const socket = new WebSocket(remoteAuthGatewayUrl, [], {
  headers: {
    Origin: "https://discord.com",
  },
});

socket.on("error", (error) => {
  console.log(error);
});

socket.on("close", (code, reason) => {
  console.log(reason.toString());
});

socket.on("message", handleMessage);

function handleMessage(data) {
  const message = JSON.parse(data.toString());

  switch (message.op) {
    // handshake
    case "hello":
      // publcic key 전송
      socket.send(
        JSON.stringify({
          op: "init",
          encoded_public_key: publicKey.toString("base64"),
        }),
      );
      break;

    // 서버가 nonce를 보냄
    case "nonce_proof":
      const encryptedNonce = Buffer.from(message.encrypted_nonce, "base64");
      const decryptedNonce = crypto.privateDecrypt(
        {
          key: rsaKeyPair.privateKey,
          oaepHash: "sha256",
        },
        encryptedNonce,
      );

      // 복호화된 nonce의 SHA256 해시를 base64로 인코딩하고
      // proof 형식으로 변환
      const hash = crypto
        .createHash("sha256")
        .update(decryptedNonce)
        .digest("base64");
      const proof = hash
        .replace(/\//g, "_")
        .replace(/\+/g, "-")
        .replace(/={1,2}$/, "");

      // 서버에 proof 전송
      socket.send(
        JSON.stringify({
          op: "nonce_proof",
          proof,
        }),
      );
      break;

    // proof 승인 성공
    case "pending_remote_init":
      // fingerprint를 가져오고 소켓 닫기
      const { fingerprint } = message;
      console.log(message);
      // socket.close();

      // QR코드 생성
      QRCode.toFile(
        "qrcode.png",
        `https://discord.com/ra/${fingerprint}`,
        {
          color: {
            dark: "#000000", // QR 코드 색
            light: "#FFFFFF", // 배경 색
          },
        },
        function (err) {
          if (err) throw err;
          console.log("QR 코드가 생성되었습니다: qrcode.png");
        },
      );

      break;

    case "pending_ticket":
      // 복호화
      const { encrypted_user_payload } = message;
      // privateKey로 복호화
      const user = crypto
        .privateDecrypt(
          {
            key: rsaKeyPair.privateKey,
            oaepHash: "sha256",
          },
          Buffer.from(encrypted_user_payload, "base64"),
        )
        .toString();

      const userData = user.split(":");
      const userId = userData[0];
      const avatar = userData[2];
      const username = userData[3];

      console.log(`사용자 ID: ${userId}`);
      console.log(`사용자 이름: ${username}`);
      console.log(`아바타: ${avatar}`);

      break;

    case "pending_login":
      console.log(message);
      break;
  }
}

// TODO
// QR 이미지를 조금 수정하고 Discord 로고 삽입
