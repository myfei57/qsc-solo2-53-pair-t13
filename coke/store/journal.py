"""分段 JSONL 流水日志。

流水只追加不重写，按 ``segment_limit`` 条一段滚动成 ``<topic>-00000.jsonl``、
``<topic>-00001.jsonl`` …。审计回放需要按段读取，因此同时提供段号列表、
单段读取和全量读取三种入口。补齐缺失段走 :meth:`JsonlJournal.write_segment`
原子落整段文件，补段路径不允许覆盖已有段，避免把补写混成重写。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any

from ..errors import StorageError


class JsonlJournal:
    """按段落写入的 JSONL 流水。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._count = 0
        self._segment = 0
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        self._count = self._existing_count()

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def root(self) -> str:
        return self._root

    def segment_index(self, count: int) -> int:
        """按"已写入条数"返回下一条应落入的段号。"""

        return max(0, count) // self._segment_limit

    def segment_path(self, index: int) -> str:
        """返回某段对应的文件路径。"""

        return self._segment_path(index)

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _existing_count(self) -> int:
        # 直接枚举段文件而不是遇缺即停：补段之前可能短暂存在中间空洞，
        # 计数口径必须覆盖空洞之后的段。
        total = 0
        for path in self.segments():
            with open(path, "r", encoding="utf-8") as handle:
                total += sum(1 for line in handle if line.strip())
        return total

    def segment_exists(self, index: int) -> bool:
        """某段文件是否已存在。"""

        return os.path.isfile(self._segment_path(index))

    def append(self, record: Any) -> str:
        """追加一条记录到当前滚动段，返回写入的段路径。"""

        with self._lock:
            index = self.segment_index(self._count)
            path = self._append_to_segment(index, record)
            self._count += 1
            self._segment = self.segment_index(self._count)
            return path

    def append_to_segment(self, index: int, record: Any) -> str:
        """把一条记录追加到指定段（跨重启续写由链状态决定段号）。"""

        if index < 0:
            raise StorageError("段号不能为负", component="store")
        with self._lock:
            path = self._append_to_segment(index, record)
            self._count += 1
            self._segment = self.segment_index(self._count - 1)
            return path

    def write_segment(self, index: int, records: list[Any]) -> str:
        """原子写入整段文件（补缺失段用），已存在的段拒绝覆盖。"""

        if index < 0:
            raise StorageError("段号不能为负", component="store")
        target = self._segment_path(index)
        with self._lock:
            if os.path.isfile(target):
                raise StorageError(f"段 {index} 已存在，补段不允许覆盖", component="store")
            try:
                handle = tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=self._root,
                    prefix=f".{self._topic}-{index:05d}.",
                    suffix=".tmp",
                    delete=False,
                )
                with handle:
                    for record in records:
                        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(handle.name, target)
            except OSError as error:
                raise StorageError(f"补写段 {index} 失败: {error}", component="store") from error
            with self._lock:
                self._count += len(records)
            return target

    def _append_to_segment(self, index: int, record: Any) -> str:
        path = self._segment_path(index)
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise StorageError(f"追加流水失败: {error}", component="store") from error
        return path

    def segments(self) -> list[str]:
        """返回已存在的段文件路径（按段号升序，允许中间有缺失段）。"""

        prefix = f"{self._topic}-"
        found: list[tuple[int, str]] = []
        try:
            names = os.listdir(self._root)
        except OSError:
            return []
        for name in names:
            if not (name.startswith(prefix) and name.endswith(".jsonl")):
                continue
            stem = name[len(prefix) : -len(".jsonl")]
            if not stem.isdigit():
                continue
            found.append((int(stem), os.path.join(self._root, name)))
        return [path for _index, path in sorted(found)]

    def read_segment(self, index: int) -> list[dict]:
        """读取指定段。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return []
        return self._read_file(path)

    def read_all(self) -> list[dict]:
        """按段号顺序读取全部记录。"""

        records: list[dict] = []
        for path in self.segments():
            records.extend(self._read_file(path))
        return records

    def count(self) -> int:
        """返回累计写入条数。"""

        with self._lock:
            return self._count

    def active_segment(self) -> int:
        """返回当前正在写入的段号。"""

        with self._lock:
            return self._segment

    def _read_file(self, path: str) -> list[dict]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        except (OSError, json.JSONDecodeError) as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error
