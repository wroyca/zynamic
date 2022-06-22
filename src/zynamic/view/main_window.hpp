/* SPDX-License-Identifier: GPL-3.0-only */

#pragma once

#include <zynamic/view/ui_main_window.h>

#include <QMainWindow>

namespace Zynamic {

class MainWindow final : public QMainWindow, public Ui::MainWindow {
  Q_OBJECT
  Q_DISABLE_COPY_MOVE(MainWindow)

public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

private:
  Ui::MainWindow* ui;
};

} // namespace Zynamic
