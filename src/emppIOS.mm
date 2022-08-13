#import "emppIOS.h"
#include "empp.hpp"

@implementation HelloWorldIOS

empp _h;

- (NSString*)getHash:(NSString* )a
{
  std::string aa([a UTF8String]);
  return [NSString stringWithUTF8String: _h._get_hash(aa).c_str()];
}

@end