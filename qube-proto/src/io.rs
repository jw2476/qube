use std::io::{Read, Write};

use crate::invalid_data;

/// An extension trait for `std::io::Read` with methods for reading integers and floating-point
/// types, as well as some Minecraft specific types like varints and varlongs.
pub trait ReadExt: Read {
    fn read_u8(&mut self) -> std::io::Result<u8>;
    fn read_u16(&mut self) -> std::io::Result<u16>;
    fn read_u32(&mut self) -> std::io::Result<u32>;
    fn read_u64(&mut self) -> std::io::Result<u64>;
    fn read_u128(&mut self) -> std::io::Result<u128>;

    fn read_i8(&mut self) -> std::io::Result<i8>;
    fn read_i16(&mut self) -> std::io::Result<i16>;
    fn read_i32(&mut self) -> std::io::Result<i32>;
    fn read_i64(&mut self) -> std::io::Result<i64>;
    fn read_i128(&mut self) -> std::io::Result<i128>;

    fn read_f32(&mut self) -> std::io::Result<f32>;
    fn read_f64(&mut self) -> std::io::Result<f64>;

    fn read_bool(&mut self) -> std::io::Result<bool>;

    fn read_varint(&mut self) -> std::io::Result<i32>;
    fn read_varlong(&mut self) -> std::io::Result<i64>;

    fn read_string(&mut self) -> std::io::Result<String>;
}

macro_rules! impl_read_simple {
    ($name:ident $ty:ty) => {
        fn $name(&mut self) -> std::io::Result<$ty> {
            let mut buffer = [0; size_of::<$ty>()];
            self.read_exact(&mut buffer)?;
            Ok(<$ty>::from_be_bytes(buffer))
        }
    };
}

impl<T: Read> ReadExt for T {
    impl_read_simple!(read_u8 u8);
    impl_read_simple!(read_u16 u16);
    impl_read_simple!(read_u32 u32);
    impl_read_simple!(read_u64 u64);
    impl_read_simple!(read_u128 u128);

    impl_read_simple!(read_i8 i8);
    impl_read_simple!(read_i16 i16);
    impl_read_simple!(read_i32 i32);
    impl_read_simple!(read_i64 i64);
    impl_read_simple!(read_i128 i128);

    impl_read_simple!(read_f32 f32);
    impl_read_simple!(read_f64 f64);

    fn read_bool(&mut self) -> std::io::Result<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(invalid_data(&format!("Read bad value for bool: {other}"))),
        }
    }

    fn read_varint(&mut self) -> std::io::Result<i32> {
        let mut value = 0_i32;

        for i in 0..5 {
            let byte: i32 = self.read_u8()?.into();
            value |= (byte & 0b0111_1111) << (i * 7);

            if (byte & 0b1000_0000) == 0 {
                return Ok(value);
            }
        }

        Err(invalid_data("Invalid varint"))
    }

    fn read_varlong(&mut self) -> std::io::Result<i64> {
        let mut value = 0_i64;

        for i in 0..10 {
            let byte: i64 = self.read_u8()?.into();
            value |= (byte & 0b0111_1111) << (i * 7);

            if (byte & 0b1000_0000) == 0 {
                return Ok(value);
            }
        }

        Err(invalid_data("Invalid varlong"))
    }

    fn read_string(&mut self) -> std::io::Result<String> {
        let Ok(length): Result<usize, _> = self.read_varint()?.try_into() else {
            return Err(invalid_data("Negative string length"));
        };

        let mut buffer = vec![0_u8; length];
        self.read_exact(&mut buffer)?;

        let Ok(string) = String::from_utf8(buffer) else {
            return Err(invalid_data("Non-UTF8 string"));
        };
        Ok(string)
    }
}

/// An extension trait for `std::io::Write` with methods for writing integers and floating-point
/// types, as well as some Minecraft specific types like varints and varlongs.
pub trait WriteExt: Write {
    fn write_u8(&mut self, value: u8) -> std::io::Result<()>;
    fn write_u16(&mut self, value: u16) -> std::io::Result<()>;
    fn write_u32(&mut self, value: u32) -> std::io::Result<()>;
    fn write_u64(&mut self, value: u64) -> std::io::Result<()>;
    fn write_u128(&mut self, value: u128) -> std::io::Result<()>;

    fn write_i8(&mut self, value: i8) -> std::io::Result<()>;
    fn write_i16(&mut self, value: i16) -> std::io::Result<()>;
    fn write_i32(&mut self, value: i32) -> std::io::Result<()>;
    fn write_i64(&mut self, value: i64) -> std::io::Result<()>;
    fn write_i128(&mut self, value: i128) -> std::io::Result<()>;

    fn write_f32(&mut self, value: f32) -> std::io::Result<()>;
    fn write_f64(&mut self, value: f64) -> std::io::Result<()>;

    fn write_bool(&mut self, value: bool) -> std::io::Result<()>;

    fn write_varint(&mut self, value: i32) -> std::io::Result<()>;
    fn write_varlong(&mut self, value: i64) -> std::io::Result<()>;

    fn write_string(&mut self, value: &str) -> std::io::Result<()>;
}

macro_rules! impl_write_simple {
    ($name:ident $ty:ty) => {
        fn $name(&mut self, value: $ty) -> std::io::Result<()> {
            self.write_all(&value.to_be_bytes())
        }
    };
}

impl<T: Write> WriteExt for T {
    impl_write_simple!(write_u8 u8);
    impl_write_simple!(write_u16 u16);
    impl_write_simple!(write_u32 u32);
    impl_write_simple!(write_u64 u64);
    impl_write_simple!(write_u128 u128);

    impl_write_simple!(write_i8 i8);
    impl_write_simple!(write_i16 i16);
    impl_write_simple!(write_i32 i32);
    impl_write_simple!(write_i64 i64);
    impl_write_simple!(write_i128 i128);

    impl_write_simple!(write_f32 f32);
    impl_write_simple!(write_f64 f64);

    fn write_bool(&mut self, value: bool) -> std::io::Result<()> {
        self.write_u8(value.into())
    }

    fn write_varint(&mut self, value: i32) -> std::io::Result<()> {
        let mut value = value.cast_unsigned();
        loop {
            let mut byte = (value & 0b0111_1111) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0b1000_0000;
            }

            self.write_u8(byte)?;

            if value == 0 {
                return Ok(());
            }
        }
    }

    fn write_varlong(&mut self, value: i64) -> std::io::Result<()> {
        let mut value = value.cast_unsigned();
        loop {
            let mut byte = (value & 0b0111_1111) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0b1000_0000;
            }

            self.write_u8(byte)?;

            if value == 0 {
                return Ok(());
            }
        }
    }

    fn write_string(&mut self, value: &str) -> std::io::Result<()> {
        let Ok(length) = i32::try_from(value.len()) else {
            return Err(invalid_data("String too long"));
        };

        self.write_varint(length)?;
        self.write_all(value.as_bytes())
    }
}
