#include "stm32f10x.h"

int main(void)
{
    // 1. 定义结构体变量 (名字是 GPIO_InitStructure)
    GPIO_InitTypeDef GPIO_InitStructure;
    
    // 2. 开启GPIOC时钟
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
    
    // 3. 配置结构体 (必须用你定义的正确名字：GPIO_InitStructure)
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_13;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	
    // 4. 初始化GPIO (参数完整)
    GPIO_Init(GPIOC, &GPIO_InitStructure);
	
    GPIO_SetBits(GPIOC,GPIO_Pin_13);
    //GPIO_ResetBits(GPIOC,GPIO_Pin_13);
	while(1)
    {
        // 你的业务代码
    }
}
