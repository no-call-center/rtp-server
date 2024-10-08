use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::{X509NameBuilder, X509};
use rtp_rs::*;
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
    attributes::ATTR_XORMAPPED_ADDRESS,
    fingerprint::FingerprintAttr,
    integrity::MessageIntegrity,
    message::{is_message, Setter, BINDING_SUCCESS},
    xoraddr::XorMappedAddress,
};

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

        let mut client_aes_key = [0u8; 16];
        let mut client_hmac_key = [0u8; 20];
        let mut client_salt = [0u8; 14];

        let mut server_aes_key = [0u8; 16];
        let mut server_hmac_key = [0u8; 20];
        let mut server_salt = [0u8; 14];

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

        let mut rtp_seq = 32514;
        let mut timestamp = 2487064536u32;
        loop {
            let (len, addr) = socket.recv_from(&mut buf).unwrap();
            let socket = socket.try_clone().unwrap();
            let a = a.clone();
            // println!("received {} bytes from {}", len, addr);

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
                // 客户端aeskey,服务端aeskey,客户端sha1key,服务端sha1key,客户端salt,服务端salt
                let mut key_material = [0u8; 100];
                ssl.ssl()
                    .export_keying_material(&mut key_material, "EXTRACTOR-dtls_srtp", None)
                    .unwrap();
                println!("key_material: {:x?}", &key_material[..]);

                // 复制给 aes_key hmac_key salt
                // client_aes_key.copy_from_slice(&key_material[..16]);
                // server_aes_key.copy_from_slice(&key_material[16..32]);

                // client_salt.copy_from_slice(&key_material[32..46]);
                // server_salt.copy_from_slice(&key_material[46..60]);
                // client_hmac_key.copy_from_slice(&key_material[60..80]);
                // server_hmac_key.copy_from_slice(&key_material[80..100]);

                // 这个是正确的密钥分布
                client_aes_key.copy_from_slice(&key_material[..16]);
                server_aes_key.copy_from_slice(&key_material[16..32]);
                client_salt.copy_from_slice(&key_material[32..46]);
                server_salt.copy_from_slice(&key_material[46..60]);

                let mut client_key = vec![];
                client_key.extend_from_slice(&client_aes_key);
                client_key.extend_from_slice(&client_salt);

                let mut server_key = vec![];
                server_key.extend_from_slice(&server_aes_key);
                server_key.extend_from_slice(&server_salt);

                unsafe {
                    let mut t_session: srtp_t = std::ptr::null_mut();
                    let mut policy: srtp_policy_t = std::mem::zeroed();

                    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
                    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                    srtp_crypto_policy_set_from_profile_for_rtp(
                        &mut policy.rtp,
                        srtp_profile_t_srtp_profile_aes128_cm_sha1_80,
                    );
                    srtp_crypto_policy_set_from_profile_for_rtcp(
                        &mut policy.rtcp,
                        srtp_profile_t_srtp_profile_aes128_cm_sha1_80,
                    );

                    policy.ssrc.value = 0u32;
                    policy.next = std::ptr::null_mut();

                    policy.key = client_key.as_ptr() as *mut _;
                    policy.ssrc.type_ = srtp_ssrc_type_t_ssrc_any_inbound;

                    let status = srtp_create(&mut t_session, &policy);
                    if status != 0 {
                        panic!("创建srtp session失败2:{}", status);
                    }
                    println!("policy2: {:#?}", policy);

                    let mut session = session.lock().unwrap();
                    *session = Some(t_session);
                }

                unsafe {
                    let mut t_session: srtp_t = std::ptr::null_mut();
                    let mut policy: srtp_policy_t = std::mem::zeroed();

                    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
                    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                    // srtp_crypto_policy_set_from_profile_for_rtp(
                    //     &mut policy.rtp,
                    //     srtp_profile_t_srtp_profile_aes128_cm_sha1_80,
                    // );
                    // srtp_crypto_policy_set_from_profile_for_rtcp(
                    //     &mut policy.rtcp,
                    //     srtp_profile_t_srtp_profile_aes128_cm_sha1_80,
                    // );

                    policy.ssrc.value = 0u32;
                    policy.next = std::ptr::null_mut();

                    policy.key = server_key.as_ptr() as *mut _;
                    policy.ssrc.type_ = srtp_ssrc_type_t_ssrc_any_outbound;

                    let status = srtp_create(&mut t_session, &policy);
                    if status != 0 {
                        panic!("创建srtp session失败2:{}", status);
                    }
                    println!("policy2: {:#?}", policy);

                    let mut session = session_send.lock().unwrap();
                    *session = Some(t_session);
                }

                println!("结束握手");

                // let mut session = session_send.lock().unwrap();
                // *session = Some(t_session);

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
                continue;
            }

            // 到这里 基本就是srtp数据
            // 解密srtp数据 data 使用 SRTP_AES128_CM_SHA1_80

            let mut packet = Vec::from(data);
            let mut len: c_int = packet.len() as c_int;
            if let Some(s) = session.lock().unwrap().as_ref() {
                if is_rtp(&buf) {
                    // rtp数据
                    unsafe {
                        let ret =
                            srtp_unprotect(s.clone(), packet.as_mut_ptr() as *mut c_void, &mut len);
                        if ret != 0 {
                            println!("解析 rtp 返回值: {}, 数据：\n{:x?}\n", ret, &packet);
                            continue;
                        }
                    }

                    let result = RtpReader::new(&packet[..len as usize]);
                    // println!("解密结果:{:#?}", result);
                    if let Ok(rtp) = result {
                        let payload = rtp.payload();
                        // println!("长度:{}", payload.len());
                        if rtp.payload_type() == 8 {
                            pcm_file.write_all(&payload).unwrap();
                            pcm_file.flush().unwrap();

                            let packet = RtpPacketBuilder::new()
                                .payload_type(8)
                                .ssrc(1097637605u32)
                                .sequence(Seq::from(rtp_seq))
                                .timestamp(timestamp)
                                .marked(rtp.mark())
                                .payload(&payload)
                                .build()
                                .unwrap();
                            timestamp += 160;
                            rtp_seq += 1;

                            let mut packet_buf = Vec::with_capacity(1000);
                            packet_buf.extend_from_slice(&packet);
                            let mut len: c_int = packet_buf.len() as c_int;
                            // println!("加密前长度:{}", len);

                            if let Some(s) = session_send.lock().unwrap().as_ref() {
                                unsafe {
                                    let ret = srtp_protect(
                                        s.clone(),
                                        packet_buf.as_mut_ptr() as *mut c_void,
                                        &mut len,
                                    );
                                    if ret != 0 {
                                        panic!("加密返回值: {}", ret);
                                    }
                                }

                                // 不管是否越界 获取packet_buf的前len个字节
                                unsafe {
                                    packet_buf.set_len(len as usize);
                                }

                                // println!("加密后: 长度{}\t内容：\n{:x?}", len, &packet_buf);

                                socket
                                    .try_clone()
                                    .unwrap()
                                    .send_to(&packet_buf, addr)
                                    .unwrap();
                            }
                        }
                    }
                } else if is_rtcp(&buf) {
                    // rtcp数据
                    unsafe {
                        let ret = srtp_unprotect_rtcp(
                            s.clone(),
                            packet.as_mut_ptr() as *mut c_void,
                            &mut len,
                        );
                        if ret != 0 {
                            panic!("解析 rtcp 返回值: {}, 数据：\n{:x?}\n", ret, &packet);
                        }
                    }

                    let rtcp_data = &packet[..len as usize];
                    println!("解密后: 长度{}\t内容：\n{:x?}\n", len, rtcp_data);
                }
            }
        }
    });

    h.await.unwrap();
    Ok(())
}

fn is_rtp(buf: &[u8]) -> bool {
    buf[1] < 200u8 && buf[0] == 0x80u8
}

fn is_rtcp(buf: &[u8]) -> bool {
    buf[1] >= 200u8 && buf[0] == 0x80u8
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
