@echo off
REM Windows批处理文件 - 自动设置OpenMP环境变量并运行训练脚本

setlocal enabledelayedexpansion

REM 设置OpenMP环境变量
set KMP_DUPLICATE_LIB_OK=TRUE

REM 运行Python训练脚本
echo ============================================================
echo 📊 启动模型训练脚本
echo ============================================================
echo.

python scripts/train_from_csv.py

REM 检查返回码
if %errorlevel% neq 0 (
    echo.
    echo ❌ 训练脚本执行失败 (错误码: %errorlevel%)
    pause
) else (
    echo.
    echo ✅ 训练脚本执行完成！
)

endlocal
