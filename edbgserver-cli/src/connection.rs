use std::{
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    net::TcpStream,
    os::fd::AsFd,
};

use gdbstub::conn::{Connection, ConnectionExt};

pub struct BufferedConnection {
    stream_reader: BufReader<TcpStream>,
    stream_writer: BufWriter<TcpStream>,
}

impl BufferedConnection {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let writer_stream = stream.try_clone()?;

        Ok(Self {
            stream_reader: BufReader::with_capacity(4096, stream),
            stream_writer: BufWriter::with_capacity(4096, writer_stream),
        })
    }

    pub fn has_buffered_data(&self) -> bool {
        !self.stream_reader.buffer().is_empty()
    }
}

impl Connection for BufferedConnection {
    type Error = io::Error;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.stream_writer.write_all(&[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.stream_writer.write_all(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.stream_writer.flush()
    }
}

impl ConnectionExt for BufferedConnection {
    fn read(&mut self) -> Result<u8, Self::Error> {
        let mut buf = [0u8; 1];
        self.stream_reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        let buf = self.stream_reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(None);
        }
        Ok(Some(buf[0]))
    }
}

impl AsFd for BufferedConnection {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.stream_reader.get_ref().as_fd()
    }
}
