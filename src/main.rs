use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::{X509NameBuilder, X509};
use std::io::{self, Write};
use std::sync::Mutex;
use std::{
    io::Read,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};
use stun::agent::TransactionId;
use stun::textattrs::Username;
use stun::{
    attributes::{ATTR_USERNAME, ATTR_XORMAPPED_ADDRESS},
    fingerprint::FingerprintAttr,
    integrity::MessageIntegrity,
    message::{is_message, Setter, BINDING_REQUEST, BINDING_SUCCESS},
    xoraddr::XorMappedAddress,
};

use webrtc_util::KeyingMaterialExporter;

// fn create_ssl_acceptor() -> Result<SslAcceptor, ErrorStack> {
//     // 生成RSA私钥
//     let rsa = Rsa::generate(2048)?;
//     let pkey = PKey::from_rsa(rsa)?;

//     // 创建X509证书
//     let mut x509_builder = X509::builder()?;
//     x509_builder.set_version(2)?;
//     x509_builder.set_pubkey(&pkey)?;

//     // 设置证书的使用者和签发者名称
//     let mut name_builder = X509NameBuilder::new()?;
//     name_builder.append_entry_by_text("CN", "localhost")?;
//     let name = name_builder.build();
//     x509_builder.set_subject_name(&name)?;
//     x509_builder.set_issuer_name(&name)?;

//     // 设置有效期
//     let not_before = Asn1Time::days_from_now(0)?;
//     let not_after = Asn1Time::days_from_now(365)?;
//     x509_builder.set_not_before(&not_before)?;
//     x509_builder.set_not_after(&not_after)?;

//     // 添加基本扩展
//     let subject_key_id = SubjectKeyIdentifier::new().build(&x509_builder.x509v3_context(None, None))?;
//     x509_builder.append_extension(subject_key_id)?;

//     // 签发证书
//     x509_builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
//     let certificate = x509_builder.build();

//     // 创建SSL接收器
//     let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;
//     acceptor.set_private_key(&pkey)?;
//     acceptor.set_certificate(&certificate)?;
//     acceptor.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")?;
//     acceptor.check_private_key()?;
//     Ok(acceptor.build())
// }

fn create_ssl_acceptor() -> io::Result<SslAcceptor> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;
    acceptor.set_private_key_file(r"mykey.key", SslFiletype::PEM)?;
    acceptor.set_certificate_chain_file(r"mycert.pem")?;
    acceptor.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80")?;
    // acceptor.set_ca_file(r"mycert.pem")?;
    acceptor.check_private_key()?;
    Ok(acceptor.build())
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建一个udp socket

    let socket = UdpSocket::bind("0.0.0.0:9001").unwrap();
    // let r = Arc::new(socket);
    // let w: Arc<UdpSocket> = r.clone();
    let acceptor = create_ssl_acceptor().unwrap();

    // let s = w.clone();
    let h = tokio::spawn(async move {
        // 接收到数据就转发到websocket
        let mut buf = [0u8; 1024];
        // let mut clients = vec![];
        let a = acceptor.clone();

        let mut aes_key = [0u8; 16];
        let mut hmac_key = [0u8; 20];
        let mut salt = [0u8; 14];

        let session = Arc::new(Mutex::new(None));

        loop {
            let (len, addr) = socket.recv_from(&mut buf).unwrap();
            let socket = socket.try_clone().unwrap();
            let a = a.clone();
            println!("received {} bytes from {}\n{:x?}\n", len, addr, &buf[..len]);

            // 收到的udp数据
            let data = &buf[..len];

            // dtls握手
            if buf[0] == 0x16 && !is_message(&buf) {
                let s = socket.try_clone().unwrap();
                println!("开始握手");

                // 用于DTLS握手的临时流
                let stream = UdpStream::new(s, addr);

                let mut ssl = a.clone().accept(stream).unwrap();

                // ssl.write_all(b"Hello from DTLS server").unwrap();

                // ssl.flush().unwrap();
                // 16字节（AES密钥）+ 20字节（SHA-1 HMAC密钥）+ 14字节（盐值）= 50字节
                let mut key_material = [0u8; 50];
                ssl.ssl()
                    .export_keying_material(&mut key_material, "EXTRACTOR-DTLS-SRTP", None)
                    .unwrap();
                println!("key_material: {:x?}", &key_material[..]);

                // 复制给 aes_key hmac_key salt
                aes_key.copy_from_slice(&key_material[..16]);
                hmac_key.copy_from_slice(&key_material[16..36]);
                salt.copy_from_slice(&key_material[36..]);

                println!("aes_key: {:x?}", aes_key);
                println!("hmac_key: {:x?}", hmac_key);
                println!("salt: {:x?}", salt);

                // key = aes_key + salt
                let mut key = vec![]; // DO NOT USE IT ON PRODUCTION
                key.extend_from_slice(&aes_key);
                key.extend_from_slice(&salt);
                key.extend_from_slice(&hmac_key);
                // 重新复制session
                let new_session = srtp::Session::with_inbound_template(srtp::StreamPolicy {
                    key: &key[..50],
                    ..Default::default()
                })
                .unwrap();
              
                println!("key_material:{:x?}\nkey:{:x?}", key_material, key);
            

                let mut session = session.lock().unwrap();
                *session = Some(new_session);

                println!("结束握手");
                // clients.push(client);
                // loop {
                //     let mut buf = [0u8; 1024];
                //     let len = ssl.read(&mut buf).unwrap();
                //     println!("received {} bytes from {}\n{:x?}\n", len, addr, &buf[..len]);
                // }

                continue;
            }

            // println!("开始进行dtls绑定");
            let mut message = stun::message::Message::new();
            message.raw = buf[..len].to_vec();

            // 处理stun消息
            if let Ok(_) = message.decode() {
                let mut out_msg = stun::message::Message {
                    typ: BINDING_SUCCESS,
                    transaction_id: message.transaction_id,
                    ..Default::default()
                };

                // println!("decoded:\n{}\n", &message);

                let xor_mapped_address = XorMappedAddress {
                    ip: addr.ip(),
                    port: addr.port(),
                };

                xor_mapped_address
                    .add_to_as(&mut out_msg, ATTR_XORMAPPED_ADDRESS)
                    .unwrap();

                out_msg.encode();

                let pwd = "UGERNEFQJVdPIzZ6YAkNEjrW".to_string();

                let message_integrity = MessageIntegrity::new_short_term_integrity(pwd);
                message_integrity.add_to(&mut out_msg).unwrap();

                let finger = FingerprintAttr;

                finger.add_to(&mut out_msg).unwrap();

                out_msg.encode();

                // println!("encoded:\n{}\n{:x?}\n\n", out_msg, &out_msg.raw);

                socket
                    .try_clone()
                    .unwrap()
                    .send_to(&out_msg.raw, addr)
                    .unwrap();
                // println!("结束dtls绑定");
            }

            // 到这里 基本就是srtp数据
            // 解密srtp数据 data 使用 SRTP_AES128_CM_SHA1_80

            let mut packet = Vec::from(data);
            if let Some(s) = session.lock().unwrap().as_mut() {
                match s.unprotect(&mut packet) {
                    Ok(()) => println!("解密后：{:?}", packet),
                    Err(err) => println!("Error unprotecting SRTP packet: {}", err),
                };
            }
        }
    });

    h.await.unwrap();
    Ok(())
}

#[derive(Debug)]
struct UdpStream {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    buffer: Option<Vec<u8>>,
}

impl UdpStream {
    fn new(socket: UdpSocket, peer_addr: SocketAddr) -> UdpStream {
        UdpStream {
            socket,
            peer_addr,
            buffer: None,
        }
    }
}

impl io::Read for UdpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(data) = self.buffer.take() {
            let len = data.len();
            buf[..len].copy_from_slice(&data);
            return Ok(len);
        }
        let mut temp_buf = [0; 1024];
        let (len, _) = self.socket.recv_from(&mut temp_buf)?;
        buf[..len].copy_from_slice(&temp_buf[..len]);
        Ok(len)
    }
}

impl io::Write for UdpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send_to(buf, self.peer_addr)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
