#ifndef _MEDIA_RTMP_H
#define _MEDIA_RTMP_H


#define MEDIA_RTMP_FEATURE_HTTP	0x01
#define MEDIA_RTMP_FEATURE_ENC	0x02
#define MEDIA_RTMP_FEATURE_SSL	0x04
#define MEDIA_RTMP_FEATURE_MFP	0x08	/* not yet supported */
#define MEDIA_RTMP_FEATURE_WRITE	0x10	/* publish, not play */
#define MEDIA_RTMP_FEATURE_HTTP2	0x20	/* server-side rtmpt */


#define MEDIA_RTMP_PROTOCOL_UNDEFINED	-1
#define MEDIA_RTMP_PROTOCOL_RTMP      0
#define MEDIA_RTMP_PROTOCOL_RTMPE     MEDIA_RTMP_FEATURE_ENC
#define MEDIA_RTMP_PROTOCOL_RTMPT     MEDIA_RTMP_FEATURE_HTTP
#define MEDIA_RTMP_PROTOCOL_RTMPS     MEDIA_RTMP_FEATURE_SSL
#define MEDIA_RTMP_PROTOCOL_RTMPTE    (MEDIA_RTMP_FEATURE_HTTP|MEDIA_RTMP_FEATURE_ENC)
#define MEDIA_RTMP_PROTOCOL_RTMPTS    (MEDIA_RTMP_FEATURE_HTTP|MEDIA_RTMP_FEATURE_SSL)
#define MEDIA_RTMP_PROTOCOL_RTMFP     MEDIA_RTMP_FEATURE_MFP

#define RTMP_PUSH_STREAM_URL    512

typedef struct _RtmpAttribute
{
    int m_iProtocol;
    char m_pcUrlArry[RTMP_PUSH_STREAM_URL];/*推流地址*/
}RtmpAttribute;

typedef struct _RtmpPacketInfo
{
    unsigned int m_uiTimeStampAbs;/*时间戳、绝对值*/
    int m_iIsSyncFrame;/*是否关键帧，1 I帧，0 非I帧*/
}RtmpPacketInfo;

void *RTMP_Create();

int RTMP_SetAttribute(void *_pvRtmpH, RtmpAttribute *_pstRtmpAttribute);

int RTMP_ConnectProtocol(void *_pvRtmpH);

int RTMP_SendVideoData(void *_pvRtmpH, char *_pcVData, int _iDataLen, RtmpPacketInfo *_pstRtmpPacketInfo);

int RTMP_SendAudioData(void *_pvRtmpH, char *_pcAData, int _iDataLen, RtmpPacketInfo *_pstRtmpPacketInfo);

int RTMP_Destroy(void *_pvRtmpH);

#endif //_MEDIA_RTMP_H

