/*
 * Copyright (c) 2017 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <string>

#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include "common.h"
#include "table_desc.h"

namespace ebpf {

using std::string;
using std::to_string;
using std::unique_ptr;
using namespace clang;

// Helper visitor for constructing a string representation of a key/leaf decl
class BMapDeclVisitor : public clang::RecursiveASTVisitor<BMapDeclVisitor> {
 public:
  explicit BMapDeclVisitor(clang::ASTContext &C, std::string &result);
  bool TraverseRecordDecl(clang::RecordDecl *Decl);
  bool VisitRecordDecl(clang::RecordDecl *Decl);
  bool VisitFieldDecl(clang::FieldDecl *Decl);
  bool VisitBuiltinType(const clang::BuiltinType *T);
  bool VisitTypedefType(const clang::TypedefType *T);
  bool VisitTagType(const clang::TagType *T);
  bool VisitPointerType(const clang::PointerType *T);
  bool VisitEnumConstantDecl(clang::EnumConstantDecl *D);
  bool VisitEnumDecl(clang::EnumDecl *D);

 private:
  clang::ASTContext &C;
  std::string &result_;
};

// Encode the struct layout as a json description
BMapDeclVisitor::BMapDeclVisitor(ASTContext &C, string &result) : C(C), result_(result) {}
bool BMapDeclVisitor::VisitFieldDecl(FieldDecl *D) {
  result_ += "\"";
  result_ += D->getName();
  result_ += "\",";
  return true;
}

bool BMapDeclVisitor::VisitEnumConstantDecl(EnumConstantDecl *D) {
  result_ += "\"";
  result_ += D->getName();
  result_ += "\",";
  return false;
}

bool BMapDeclVisitor::VisitEnumDecl(EnumDecl *D) {
  result_ += "[\"";
  result_ += D->getName();
  result_ += "\", [";
  for (auto it = D->enumerator_begin(); it != D->enumerator_end(); ++it) {
    TraverseDecl(*it);
  }
  result_.erase(result_.end() - 1);
  result_ += "], \"enum\"]";
  return false;
}

bool BMapDeclVisitor::TraverseRecordDecl(RecordDecl *D) {
  // skip children, handled in Visit...
  if (!WalkUpFromRecordDecl(D))
    return false;
  return true;
}
bool BMapDeclVisitor::VisitRecordDecl(RecordDecl *D) {
  result_ += "[\"";
  result_ += D->getName();
  result_ += "\", [";
  for (auto F : D->getDefinition()->fields()) {
    if (F->isAnonymousStructOrUnion()) {
      if (const RecordType *R = dyn_cast<RecordType>(F->getType()))
        TraverseDecl(R->getDecl());
      result_ += ", ";
      continue;
    }
    result_ += "[";
    TraverseDecl(F);
    if (const ConstantArrayType *T = dyn_cast<ConstantArrayType>(F->getType()))
      result_ += ", [" + T->getSize().toString(10, false) + "]";
    if (F->isBitField())
      result_ += ", " + to_string(F->getBitWidthValue(C));
    result_ += "], ";
  }
  if (!D->getDefinition()->field_empty())
    result_.erase(result_.end() - 2);
  result_ += "]";
  if (D->isUnion())
    result_ += ", \"union\"";
  else if (D->isStruct())
    result_ += ", \"struct\"";
  result_ += "]";
  return true;
}
// pointer to anything should be treated as terminal, don't recurse further
bool BMapDeclVisitor::VisitPointerType(const PointerType *T) {
  result_ += "\"unsigned long long\"";
  return false;
}
bool BMapDeclVisitor::VisitTagType(const TagType *T) {
  return TraverseDecl(T->getDecl()->getDefinition());
}
bool BMapDeclVisitor::VisitTypedefType(const TypedefType *T) { return TraverseDecl(T->getDecl()); }
bool BMapDeclVisitor::VisitBuiltinType(const BuiltinType *T) {
  result_ += "\"";
  result_ += T->getName(C.getPrintingPolicy());
  result_ += "\"";
  return true;
}

class JsonMapTypesVisitor : public virtual MapTypesVisitor {
 public:
  virtual void Visit(TableDesc &desc, clang::ASTContext &C, clang::QualType key_type,
                     clang::QualType leaf_type) {
    BMapDeclVisitor v1(C, desc.key_desc), v2(C, desc.leaf_desc);
    v1.TraverseType(key_type);
    v2.TraverseType(leaf_type);
  }
};

unique_ptr<MapTypesVisitor> createJsonMapTypesVisitor() {
  return make_unique<JsonMapTypesVisitor>();
}

}  // namespace ebpf
