#!/usr/bin/bash

check() {
    return 0
}

depends() {
    retrun 0
}

install() {
    if [ -d "/usr/lib/firmware/updates" ]; then
        echo "firmware update folder exist, firmware deployment in initramfs will be taken care by dracut conf"
    else
        echo "firmware update folder is not present, deploy firmwares from /usr/lib/firmware/qcom to initramfs..."
        inst_simple /usr/lib/firmware/qcom/x1e80100/adsp.mbn
        inst_simple /usr/lib/firmware/qcom/x1e80100/adsp_dtb.mbn
        inst_simple /usr/lib/firmware/qcom/x1e80100/cdsp.mbn
        inst_simple /usr/lib/firmware/qcom/x1e80100/cdsp_dtb.mbn
        inst_simple /usr/lib/firmware/qcom/qcs6490/adsp.mbn
        inst_simple /usr/lib/firmware/qcom/qcs6490/cdsp.mbn
        inst_simple /usr/lib/firmware/qcom/sa8775p/adsp.mbn
        inst_simple /usr/lib/firmware/qcom/sa8775p/cdsp0.mbn
        inst_simple /usr/lib/firmware/qcom/sa8775p/cdsp1.mbn
        inst_simple /usr/lib/firmware/qcom/sa8775p/gpdsp0.mbn
        inst_simple /usr/lib/firmware/qcom/sa8775p/gpdsp1.mbn
        inst_simple /usr/lib/firmware/qcom/qcs8300/adsp.mbn
        inst_simple /usr/lib/firmware/qcom/qcs8300/cdsp0.mbn
        inst_simple /usr/lib/firmware/qcom/qcs8300/gpdsp0.mbn
    fi
}
