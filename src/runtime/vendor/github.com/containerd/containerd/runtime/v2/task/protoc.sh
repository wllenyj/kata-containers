protoc \
    -I=. \
    -I=/home/wanglei01/opt/open/go/src/github.com/gogo/protobuf \
    -I=/home/wanglei01/opt/open/go/src:/usr/local/include \
    --proto_path=./ \
    --gogottrpc_out=plugins=ttrpc,import_path=./,Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mprefix=:./ \
    image.proto
