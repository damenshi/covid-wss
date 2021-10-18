#ifndef _STR_H
#define _STR_H

/*
 * 封装简单字符串操作
 */
struct str_s {
  /* 数据实际长度  */
  unsigned int length;
  /* 数据分配的最大空间，如果length > cap则需要重新扩容    */
  unsigned int cap;
  /* 数据指针  */
  unsigned char *data;
};

/**
 * \breif  释放空间
 *
 * \param str  待释放的指针地址
 *
 */
void str_release(struct str_s *str);

/**
 * \breif   设置数据值 
 *
 * \param str  待设置的指针地址
 * \param length 待设置的数据长度
 * \param data  待设置的数据
 * \return  失败则返回-1，成功则返回实际数据长度
 */
int str_set(struct str_s *str, unsigned int length, unsigned char *data);

/**
 * \breif   获取数据值 
 *
 * \param str  指针地址
 * \return  失败则返回null，成功则返回实际数据首地址
 */
unsigned char *str_get(struct str_s *str);

/**
 * \breif   分配空间
 *
 * \return  失败则返回null，成功则返回分配的首地址
 */
struct str_s *str_create(void);

/**
 * \breif   返回数据的实际长度
 *
 */
unsigned int str_length(struct str_s *str);

/**
 * \breif   两个数据拼接在一起
 *
 * \param dst 目的指针地址
 * \param src 源指针地址
 * \return  dst首地址
 */
struct str_s *str_add(struct str_s *dst, struct str_s *src);

/**
 * \breif   比较两组数据是否相等 
 *
 * \param dst 目的指针地址
 * \param src 源指针地址
 * \return   返回比较的结果，0为相等，其它为不相等
 */
int str_compare(struct str_s *str1, struct str_s *str2);

int str_set_length(struct str_s *str1, int length);

#endif /* STR_H*/
