use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::{X509NameBuilder, X509};
use srtp2_sys::*;
use std::ffi::c_void;
use std::io::{self, Write};
use std::mem::forget;
use std::os::raw::c_int;
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
use webrtc_util::marshal::{Marshal, MarshalSize, Unmarshal};
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

    unsafe {
        srtp_init();
    }
    // let s = w.clone();
    let h = tokio::spawn(async move {
        // 接收到数据就转发到websocket
        let mut buf = [0u8; 1024];
        // let mut clients = vec![];
        let a = acceptor.clone();

        let mut aes_key = [0u8; 16];
        let mut hmac_key = [0u8; 20];
        let mut salt = [0u8; 14];

        let mut client_aes_key = [0u8; 16];
        let mut client_hmac_key = [0u8; 20];
        let mut client_salt = [0u8; 14];

        let mut pcm_file = std::fs::File::create("test.pcm").unwrap();

        // let mut session = srtp::Session::with_inbound_template(srtp::StreamPolicy {
        //     ..Default::default()
        // })
        // .unwrap();

        let session = Arc::new(Mutex::new(None));

        let session_send = Arc::new(Mutex::new(None));

        // match session.unprotect(&mut packet) {
        //     Ok(()) => println!("SRTP packet unprotected"),
        //     Err(err) => println!("Error unprotecting SRTP packet: {}", err),
        // };

        let mut rtp_seq = 0;
        let mut timestamp = 2154u32;
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
                // 分布方式 服务端aeskey,客户端aeskey,服务端sha1key,客户端sha1key,服务端salt,客户端salt
                let mut key_material = [0u8; 100];
                ssl.ssl()
                    .export_keying_material(&mut key_material, "EXTRACTOR-dtls_srtp", None)
                    .unwrap();
                println!("key_material: {:x?}", &key_material[..]);

                // // 复制给 aes_key hmac_key salt
                aes_key.copy_from_slice(&key_material[..16]);
                client_aes_key.copy_from_slice(&key_material[16..32]);
                hmac_key.copy_from_slice(&key_material[32..52]);
                client_hmac_key.copy_from_slice(&key_material[52..72]);
                salt.copy_from_slice(&key_material[72..86]);
                client_salt.copy_from_slice(&key_material[86..]);

                // println!("aes_key: {:x?}", aes_key);
                // println!("hmac_key: {:x?}", hmac_key);
                // println!("salt: {:x?}", salt);

                // 重新复制session
                // let new_session = srtp::Session::with_inbound_template(srtp::StreamPolicy {
                //     key: &key_material[..30],
                //     ..Default::default()
                // })
                // .unwrap();

                let mut key = vec![];
                key.extend_from_slice(&aes_key);
                key.extend_from_slice(&hmac_key);
                key.extend_from_slice(&salt);

                let mut policy: srtp_policy_t = unsafe { std::mem::zeroed() };

                // 接收rtp的策略
                unsafe {
                    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
                    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                    policy.key = key.as_ptr() as *mut _;
                    policy.ssrc.type_ = srtp_ssrc_type_t_ssrc_any_inbound;
                    policy.next = std::ptr::null_mut();
                }

                println!("policy: {:#?}", &policy.rtp);

                let mut t_session: srtp_t = std::ptr::null_mut();
                unsafe {
                    let status = srtp_create(&mut t_session, &policy);
                    if (status != 0) {
                        panic!("创建srtp session失败:{}", status);
                    }
                }

                let mut session = session.lock().unwrap();
                *session = Some(t_session);
                println!("结束握手");
           

                let mut client_key = vec![];
                client_key.extend_from_slice(&client_aes_key);
                client_key.extend_from_slice(&client_hmac_key);
                client_key.extend_from_slice(&client_salt);
                let mut policy: srtp_policy_t = unsafe { std::mem::zeroed() };

                // 发送rtp的策略
                unsafe {
                    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
                    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                    policy.key = client_key.as_ptr() as *mut _;
                    policy.ssrc.type_ = srtp_ssrc_type_t_ssrc_specific;
                    policy.ssrc.value = 1097637605u32;
                    policy.next = std::ptr::null_mut();
                }

                println!("policy: {:#?}", &policy.rtp);

                let mut t_session: srtp_t = std::ptr::null_mut();
                unsafe {
                    let status = srtp_create(&mut t_session, &policy);
                    if (status != 0) {
                        panic!("创建srtp session失败:{}", status);
                    }
                }

                let mut session = session_send.lock().unwrap();
                *session = Some(t_session);

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
            let mut len: c_int = packet.len() as c_int;
            if let Some(s) = session.lock().unwrap().as_ref() {
                unsafe {
                    let ret =
                        srtp_unprotect(s.clone(), packet.as_mut_ptr() as *mut c_void, &mut len);
                    println!("解析返回值: {}", ret);
                }
                println!("解密后: \n{:x?}", &packet);

                let mut buf = &packet[..];
                let result = rtp::packet::Packet::unmarshal(&mut buf);
                println!("解密结果:{:#?}", result);
                if let Ok(rtp) = result {
                    let data = rtp.payload.clone();
                    println!("长度:{}", data.len());
                    if rtp.header.payload_type == 8 {
                        pcm_file.write_all(&data[..160]).unwrap();
                        pcm_file.flush().unwrap();

                        if let Some(s) = session_send.lock().unwrap().as_ref() {
                            let mut packet = rtp.clone();
                            packet.header.ssrc = 1097637605u32;
                            packet.header.sequence_number = packet.header.sequence_number+160;
                            packet.header.timestamp = timestamp;
                            rtp_seq += 1;
                            
                            timestamp += 160;
                            let mut packet_buf = Vec::with_capacity(1000);
                            let t_buf = packet.marshal().unwrap();
                            packet_buf.extend_from_slice(&t_buf);
                            let mut len: c_int = packet_buf.len() as c_int;
                            println!("加密前长度:{}", len);
                            
                            unsafe {
                                let ret = srtp_protect(
                                    s.clone(),
                                    packet_buf.as_mut_ptr() as *mut c_void,
                                    &mut len,
                                );
                                println!("加密返回值: {}", ret);
                            }
                            println!("加密后: 长度{}\t内容：\n{:x?}", len, &packet_buf);

                            
                            // unsafe {
                            //     let ret = srtp_unprotect(
                            //         s.clone(),
                            //         packet_buf.as_mut_ptr() as *mut c_void,
                            //         &mut len,
                            //     );
                            //     println!("服务端解析返回值: {}", ret);
                            // }
                            // println!("服务端解密后: \n{:x?}", &packet_buf);
                            socket
                                .try_clone()
                                .unwrap()
                                .send_to(&packet_buf, addr)
                                .unwrap();
                        }
                    }
                }
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
