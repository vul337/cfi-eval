// Modified from https://github.com/LucioFranco/tokio-bincode (MIT)
// Copyright (c) 2019 Lucio Franco

use bincode::Config;
use bytes::BytesMut;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use tokio::codec::{Decoder, Encoder};

use tokio::codec::length_delimited::LengthDelimitedCodec;

/// Bincode based codec for use with `tokio-codec`
pub struct BinCodec<T> {
    lower: LengthDelimitedCodec,
    config: Config,
    _pd: PhantomData<T>,
}

impl<T> BinCodec<T> {
    /// Provides a bincode based codec
    pub fn new() -> Self {
        let config = bincode::config();
        BinCodec::with_config(config)
    }

    /// Provides a bincode based codec from the bincode config
    pub fn with_config(config: Config) -> Self {
        let lower = LengthDelimitedCodec::new();
        BinCodec {
            lower,
            config,
            _pd: PhantomData,
        }
    }
}

impl<T> Decoder for BinCodec<T>
where
    for<'de> T: Deserialize<'de>,
{
    type Item = T;
    type Error = bincode::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(if let Some(buf) = self.lower.decode(src)? {
            Some(self.config.deserialize(&buf)?)
        } else {
            None
        })
    }
}

impl<T> Encoder for BinCodec<T>
where
    T: Serialize,
{
    type Item = T;
    type Error = bincode::Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = self.config.serialize(&item)?;
        self.lower.encode(bytes.into(), dst)?;
        Ok(())
    }
}

impl<T> fmt::Debug for BinCodec<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BinCodec").finish()
    }
}

// XXX explicitly declare the protocol of length delimited.
pub struct SyncBincode<T, U> {
    inner: T,
    _marker: PhantomData<U>,
}

impl<T, U> SyncBincode<T, U>
where
    T: Read + Write,
    U: Serialize + DeserializeOwned,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn write(&mut self, msg: &U) -> io::Result<()> {
        let buf = bincode::serialize(msg).map_err(|_| io::ErrorKind::InvalidData)?;
        let header = (buf.len() as u32).to_be_bytes();
        self.inner.write_all(&header)?;
        self.inner.write_all(&buf)?;
        self.inner.flush()?;
        Ok(())
    }

    pub fn read(&mut self) -> io::Result<U> {
        let mut header = [0, 0, 0, 0];
        self.inner.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header);
        let mut buf = vec![0; len as usize];
        self.inner.read_exact(&mut buf)?;
        let r = bincode::deserialize(&buf).map_err(|_| io::ErrorKind::InvalidData)?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{Future, Sink, Stream};
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;
    use tokio::{
        codec::Framed,
        net::{TcpListener, TcpStream},
        runtime::current_thread,
    };

    #[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
    enum Mock {
        One(Vec<u8>),
        Two,
    }

    #[test]
    fn test_codec() {
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 15151);
        let echo = TcpListener::bind(&addr).unwrap();

        let jh = std::thread::spawn(move || {
            current_thread::run(
                echo.incoming()
                    .map_err(bincode::Error::from)
                    .take(1)
                    .for_each(|stream| {
                        let (w, r) = Framed::new(stream, BinCodec::<Mock>::new()).split();
                        r.forward(w).map(|_| ())
                    })
                    .map_err(|_| ()),
            )
        });

        let client = TcpStream::connect(&addr).wait().unwrap();
        let client = Framed::new(client, BinCodec::<Mock>::new());

        let client = client.send(Mock::One(vec![0; 10000])).wait().unwrap();

        let (got, client) = match client.into_future().wait() {
            Ok(x) => x,
            Err((e, _)) => panic!(e),
        };

        assert_eq!(got, Some(Mock::One(vec![0; 10000])));

        let client = client.send(Mock::Two).wait().unwrap();

        let (got2, client) = match client.into_future().wait() {
            Ok(x) => x,
            Err((e, _)) => panic!(e),
        };

        assert_eq!(got2, Some(Mock::Two));

        drop(client);
        jh.join().unwrap();
    }
}
