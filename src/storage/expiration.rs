use std::fmt;
use std::str::FromStr;

use cosmwasm_std::{BlockInfo, Timestamp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
/// Expiration represents a point in time when some event happens.
/// It can compare with a BlockInfo and will return is_expired() == true
/// once the condition is hit (and for every block in the future)
pub enum Expiration {
    /// AtHeight will expire when `env.block.height` >= height
    AtHeight(u64),
    /// AtTime will expire when `env.block.time` >= time
    AtTime(Timestamp),
    /// Never will never expire. Used to express the empty variant
    Never {},
}

impl fmt::Display for Expiration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expiration::AtHeight(height) => write!(f, "expiration height: {}", height),
            Expiration::AtTime(time) => write!(f, "expiration time: {}", time.seconds()),
            Expiration::Never {} => write!(f, "expiration: never"),
        }
    }
}

impl FromStr for Expiration {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("expiration time") {
            return Ok(Expiration::AtTime(Timestamp::from_seconds(
                s.strip_prefix("expiration time: ")
                    .unwrap()
                    .parse()
                    .unwrap(),
            )));
        }
        if s.contains("expiration height") {
            return Ok(Expiration::AtHeight(
                s.strip_prefix("expiration height: ")
                    .unwrap()
                    .parse()
                    .unwrap(),
            ));
        }
        if s.contains("expiration: never") {
            return Ok(Expiration::Never {});
        }
        Err(())
    }
}

/// The default (empty value) is to never expire
impl Default for Expiration {
    fn default() -> Self {
        Expiration::Never {}
    }
}

impl Expiration {
    pub fn is_expired(&self, block: &BlockInfo) -> bool {
        match self {
            Expiration::AtHeight(height) => block.height >= *height,
            Expiration::AtTime(time) => return block.time >= *time,
            Expiration::Never {} => false,
        }
    }

    pub fn as_seconds(&self) -> u64 {
        match self {
            Expiration::AtHeight(height) => *height,
            Expiration::AtTime(time) => time.seconds(),
            Expiration::Never {} => 0,
        }
    }
}

impl Expiration {
    pub fn is_triggered(&self, block: &BlockInfo) -> bool {
        match self {
            Expiration::AtHeight(height) => block.height >= *height,
            Expiration::AtTime(time) => block.time >= *time,
            Expiration::Never {} => false,
        }
    }
}

pub const WEEK: Duration = Duration::Time(7 * 24 * 60 * 60);

/// Duration is a delta of time. You can add it to a BlockInfo or Expiration to
/// move that further in the future. Note that an height-based Duration and
/// a time-based Expiration cannot be combined
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Duration {
    Height(u64),
    /// Time in seconds
    Time(u64),
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Duration::Height(height) => write!(f, "\"height\": {}", height),
            Duration::Time(time) => write!(f, "\"time\": {}", time),
        }
    }
}

impl Duration {
    /// Create an expiration for Duration after current block
    pub fn after(&self, block: &BlockInfo) -> Expiration {
        match self {
            Duration::Height(h) => Expiration::AtHeight(block.height + h),
            Duration::Time(t) => Expiration::AtTime(block.time.plus_seconds(*t)),
        }
    }
}
