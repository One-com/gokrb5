package gokrb5

// #include <krb5.h>
/*

#include "./data.h"

krb5_data*
make_data_array(unsigned int size)
{
    return malloc(size * sizeof(krb5_data));
}

void
free_data_array_with_content(krb5_data *arr, unsigned int size) {
  int i;
  void *p;
  for (i=0; i<size; i++) {
    p = arr[i].data;
    if (p != 0) {
      free(arr[i].data);
    }
  }
  free(arr);
}

void
set_data_array_idx(krb5_data *arr, int idx, void *data, unsigned int len) {
     arr[idx] = make_data(data, len);
}
*/
import "C"

import (
	"unsafe"
)

func makeKrb5DataArray(size uint) *C.krb5_data {
	return C.make_data_array(C.uint(size))
}

func freeKrb5DataArrayWithContent(arr *C.krb5_data, count uint) {
	C.free_data_array_with_content(arr, C.uint(count))
}

func setKrb5DataArrayIdx(arr *C.krb5_data, idx int, data unsafe.Pointer, len uint) {
	C.set_data_array_idx(arr, C.int(idx), data, C.uint(len))
}
