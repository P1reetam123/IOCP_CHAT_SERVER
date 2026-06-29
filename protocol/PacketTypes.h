#pragma once

// Prefixed with PKT_ to avoid conflicts with Windows macros
// (Windows defines FILE_END as a macro in winbase.h/stdio.h)
enum PacketType
{
    PKT_LOGIN = 1,
    PKT_LOGOUT,          // 2
    PKT_PRIVATE_MESSAGE, // 3
    PKT_GROUP_MESSAGE,   // 4
    PKT_CREATE_GROUP,    // 5
    PKT_JOIN_GROUP,      // 6
    PKT_LEAVE_GROUP,     // 7
    PKT_FILE_START,      // 8
    PKT_FILE_CHUNK,      // 9
    PKT_FILE_END ,
    FILE_DWNLD_DISCONNECT_REQUEST ,       // 10
    PKT_ACKNOWLEDGMENT, //11
    PKT_RESUME,
    PKT_STATUS,
    FILE_STATUS ,
    ROUND_STATUS  ,
    DOWNLOAD_LINK,
    DOWNLOAD_REQUEST,
    PKT_ROUND_END,
    PKT_FILE_ACK,
   PKT_FILE_ERROR,
   FILE_START_RESPONSE,
   PKT_SIGN_UP,
   PKT_OTP_REQ,
   PKT_OTP_VERIFY,
   PKT_TOKEN,
   PKT_REFRESH,
   PKT_TOKEN_GRANTED,
   PKT_AUTH_FAIL,
   PKT_SIGNUP_PENDING
};