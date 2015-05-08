
use std::io;
use std::convert::From;
use cbor::CborError;

//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ResponseError {
    NoData,
    InvalidRequest,
}

//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum InterfaceError {
    Abort,
    Response(ResponseError),
}

impl From<ResponseError> for InterfaceError {
    fn from(e: ResponseError) -> InterfaceError {
        InterfaceError::Response(e)
    }
}

//------------------------------------------------------------------------------
#[derive(Debug)]
pub enum RoutingError {
    DontKnow,
    FailedToBootstrap,
    Interface(InterfaceError),
    Io(io::Error),
    CborError(CborError),
    Response(ResponseError),
}


impl From<()> for RoutingError {
    fn from(e: ()) -> RoutingError { RoutingError::DontKnow }
}

impl From<ResponseError> for RoutingError {
    fn from(e: ResponseError) -> RoutingError { RoutingError::Response(e) }
}

impl From<CborError> for RoutingError {
    fn from(e: CborError) -> RoutingError { RoutingError::CborError(e) }
}

impl From<io::Error> for RoutingError {
    fn from(e: io::Error) -> RoutingError { RoutingError::Io(e) }
}

impl From<InterfaceError> for RoutingError {
    fn from(e: InterfaceError) -> RoutingError { RoutingError::Interface(e) }
}

